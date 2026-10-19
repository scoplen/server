// SPDX-License-Identifier: AGPL-3.0-only
//! Durable primitives for the append-ordered sync store.
//!
//! This module deliberately stops at storage. Authentication, envelope validation, policy
//! filtering, and HTTP/CBOR representations belong to the sync service and its protocol crates.

#![forbid(unsafe_code)]

use std::{
    collections::{HashMap, HashSet},
    time::{SystemTime, UNIX_EPOCH},
};

use sqlx::{Postgres, Row, Sqlite, Transaction};
use thiserror::Error;

use crate::{PostgresStore, RelationalStore, SqliteStore, account_keys::AccountId};

/// Maximum envelope size from the sync protocol's default limits.
pub const MAX_ENVELOPE_BYTES: usize = 260 * 1024;
/// Maximum number of objects in one write batch.
pub const MAX_BATCH_OBJECTS: usize = 500;
/// Maximum combined envelope size in one write batch.
pub const MAX_BATCH_BYTES: usize = 4 * 1024 * 1024;
/// Maximum page size from the sync protocol.
pub const MAX_PAGE_SIZE: u16 = 1_000;
/// Number of milliseconds in one day, used by retention workers.
const MILLIS_PER_DAY: i64 = 86_400_000;
/// Historical versions are retained for at most this many days.
pub const VERSION_RETENTION_DAYS: i64 = 30;
/// Tombstones are eligible for time-based purging after this many days.
pub const TOMBSTONE_PURGE_AFTER_DAYS: i64 = 180;
/// Maximum size of the opaque wrapped epoch-1 shared-vault key.
pub const MAX_SHARED_VAULT_KEY_BYTES: usize = 64 * 1024;
/// Maximum number of member wraps in one epoch publication.
pub const MAX_SHARED_VAULT_EPOCH_WRAPS: usize = 1_000;
/// Maximum number of non-retired epochs in a shared-vault key response.
pub const MAX_SHARED_VAULT_KEY_EPOCHS: usize = 64;
/// Maximum number of non-retired epochs supplied when adding a member.
pub const MAX_SHARED_VAULT_MEMBER_EPOCHS: usize = MAX_SHARED_VAULT_KEY_EPOCHS;
/// Maximum encoded size of one shared-vault key response.
pub const MAX_SHARED_VAULT_KEYS_BODY_BYTES: usize = 4 * 1024 * 1024;
/// Maximum number of current object ids in a vault, including tombstones.
pub const MAX_OBJECTS_PER_VAULT: u64 = 100_000;
/// Maximum number of shared vaults visible to one account.
pub const MAX_SHARED_VAULTS_PER_ACCOUNT: u64 = 1_000;
/// Maximum number of current account members in a shared vault.
pub const MAX_MEMBERS_PER_SHARED_VAULT: u64 = 1_000;

/// SQLite sync cardinality limits selected for one deployment.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct SyncCardinalityLimits {
    pub max_objects_per_vault: u64,
    pub max_shared_vaults_per_account: u64,
    pub max_members_per_shared_vault: u64,
}

impl Default for SyncCardinalityLimits {
    fn default() -> Self {
        Self {
            max_objects_per_vault: MAX_OBJECTS_PER_VAULT,
            max_shared_vaults_per_account: MAX_SHARED_VAULTS_PER_ACCOUNT,
            max_members_per_shared_vault: MAX_MEMBERS_PER_SHARED_VAULT,
        }
    }
}

impl SyncCardinalityLimits {
    /// Validate values before opening a store or advertising them to clients.
    ///
    /// # Errors
    ///
    /// Returns the invalid setting and its supported range.
    pub fn validate(self) -> Result<(), String> {
        for (name, value) in [
            ("sync.max_objects_per_vault", self.max_objects_per_vault),
            ("sync.max_shared_vaults_per_account", self.max_shared_vaults_per_account),
        ] {
            if value == 0 || value > i64::MAX as u64 {
                return Err(format!("{name} must be between 1 and {}", i64::MAX));
            }
        }
        if self.max_members_per_shared_vault == 0
            || self.max_members_per_shared_vault > MAX_SHARED_VAULT_EPOCH_WRAPS as u64
        {
            return Err(format!(
                "sync.max_members_per_shared_vault must be between 1 and {MAX_SHARED_VAULT_EPOCH_WRAPS}; epoch publication requires one wrap per member"
            ));
        }
        Ok(())
    }
}

/// A 16-byte vault identifier. UUID version and variant validation belongs to the protocol layer.
pub type VaultId = [u8; 16];
/// A 16-byte object identifier.
pub type ObjectId = [u8; 16];
/// A 16-byte enrolled device identifier.
pub type DeviceId = [u8; 16];

/// Shared-vault metadata visible to one current account member.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SharedVaultDescriptor {
    pub vault_id: VaultId,
    pub sequence: u64,
    pub key_epoch: u64,
    pub rotation_pending: bool,
}

/// Account-visible vault metadata for the session handshake.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct AccountVaultDescriptor {
    pub vault_id: VaultId,
    pub kind: VaultKind,
    pub sequence: u64,
    pub key_epoch: u64,
    pub rotation_pending: bool,
}

/// The vault classes currently defined by the sync protocol.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum VaultKind {
    /// A vault owned by one account.
    Personal,
    /// A vault shared by account members.
    Shared,
    /// A policy-authoritative organization vault.
    Organization,
}

/// One opaque wrapped key visible to a shared-vault member.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SharedVaultKey {
    /// Positive non-retired key epoch.
    pub epoch: u64,
    /// Account-bound opaque vault-key wrap.
    pub wrapped_vault_key: Vec<u8>,
}

/// One member-specific wrap supplied when publishing a new epoch.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SharedVaultEpochWrap {
    /// Current member account identifier.
    pub account_id: AccountId,
    /// Opaque account-bound vault-key wrap.
    pub wrapped_vault_key: Vec<u8>,
}

impl VaultKind {
    const fn as_str(self) -> &'static str {
        match self {
            Self::Personal => "personal",
            Self::Shared => "shared",
            Self::Organization => "organization",
        }
    }
}

/// One opaque object write after the protocol layer has authenticated the caller.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ObjectWrite {
    /// Object being created or replaced.
    pub object_id: ObjectId,
    /// Sequence the caller merged from, or `None` for a new object.
    pub base_sequence: Option<u64>,
    /// Encrypted envelope bytes. The store never interprets these bytes.
    pub envelope: Vec<u8>,
    /// Validated vault-key epoch supplied by the protocol authentication boundary.
    pub key_epoch: u64,
    /// Whether this write is a tombstone.
    pub tombstone: bool,
    /// Device that signed the envelope, when the caller has supplied the verified identity.
    pub signer_device_id: Option<DeviceId>,
}

/// A current object version returned by a change query or CAS conflict.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SyncChange {
    /// Object identifier.
    pub object_id: ObjectId,
    /// Server-assigned sequence number.
    pub sequence: u64,
    /// Opaque envelope bytes.
    pub envelope: Vec<u8>,
    /// Vault-key epoch used by this version.
    pub key_epoch: u64,
    /// Tombstone marker supplied by the writer.
    pub tombstone: bool,
    /// Verified signer device identifier, if one was supplied.
    pub signer_device_id: Option<DeviceId>,
}

/// One result from an accepted write.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct WriteReceipt {
    /// Object identifier.
    pub object_id: ObjectId,
    /// Sequence assigned to this object in the batch.
    pub sequence: u64,
}

/// A page of current object versions at one vault snapshot.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ChangePage {
    /// Current versions eligible after the caller's cursor.
    pub changes: Vec<SyncChange>,
    /// Cursor for the next request.
    pub next_cursor: u64,
    /// Whether another eligible current version exists at the same snapshot.
    pub more: bool,
}

/// A page of current object versions for full reconciliation.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct SnapshotPage {
    /// Current versions in snapshot order.
    pub objects: Vec<SyncChange>,
    /// Cursor for the next snapshot request.
    pub next_cursor: u64,
    /// Whether another current version exists at the same snapshot.
    pub more: bool,
}

/// The object state that caused a compare-and-swap conflict.
#[derive(Debug, Clone, Eq, PartialEq)]
pub struct ConflictEntry {
    /// Object supplied by the rejected write.
    pub object_id: ObjectId,
    /// Current object state, or `None` when the object is still absent.
    pub current: Option<SyncChange>,
}

/// Result of a retention pass over one vault.
#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub struct PurgeReport {
    /// Historical version rows removed, including rows removed with a tombstone.
    pub pruned_versions: u64,
    /// Current tombstoned objects removed from the vault.
    pub purged_tombstones: u64,
    /// The vault's resulting purge horizon.
    pub purge_horizon: u64,
}

/// Storage failures for sync operations.
#[derive(Debug, Error)]
pub enum SyncStoreError {
    /// The requested vault is not present.
    #[error("sync vault does not exist")]
    VaultNotFound,
    /// A shared vault with this identifier is already present.
    #[error("sync vault already exists")]
    VaultAlreadyExists,
    /// The requested epoch does not immediately follow the current epoch.
    #[error("sync vault epoch conflicts with current epoch {current_epoch}")]
    EpochConflict { current_epoch: u64 },
    /// The requested epoch is not currently served by the vault.
    #[error("sync vault epoch does not exist: {epoch}")]
    EpochNotFound { epoch: u64 },
    /// The newest served epoch cannot be retired.
    #[error("sync vault epoch is the newest served epoch: {epoch}")]
    EpochNewest { epoch: u64 },
    /// A current object still references the epoch.
    #[error("sync vault epoch is still referenced by current objects: {epoch}")]
    EpochInUse { epoch: u64 },
    /// A write references an epoch that has already been retired.
    #[error("sync vault epoch has been retired: {epoch}")]
    EpochRetired { epoch: u64 },
    /// Epoch retirement is only supported for shared vaults.
    #[error("sync vault epoch retirement is only supported for shared vaults")]
    UnsupportedVaultKind,
    /// The supplied wraps do not exactly match the current member set.
    #[error("sync vault epoch member set does not match current members")]
    MemberSetMismatch,
    /// A mutation would make a member's complete key response exceed the wire bounds.
    #[error("shared-vault key response would exceed the fixed protocol bounds")]
    VaultKeyResponseLimit,
    /// The target account is already a member of the vault.
    #[error("sync vault member already exists")]
    MemberAlreadyExists,
    /// The supplied member wraps do not cover the current epoch set.
    #[error("sync vault member epochs do not match current epochs")]
    MemberEpochMismatch,
    /// The requested account is not a current member of the vault.
    #[error("sync vault member does not exist")]
    MemberNotFound,
    /// Removing this account would leave the shared vault without an admin.
    #[error("sync vault cannot remove its last admin")]
    LastAdmin,
    /// The epoch wrap list is empty, oversized, unsorted, or duplicated.
    #[error("sync vault epoch wraps are invalid")]
    InvalidEpochWraps,
    /// The member epoch-wrap list is empty, oversized, unsorted, or duplicated.
    #[error("sync vault member wraps are invalid")]
    InvalidMemberWraps,
    /// The initial shared-vault key wrap is empty.
    #[error("shared-vault key wrap must not be empty")]
    EmptyVaultKey,
    /// The initial shared-vault key wrap exceeds the protocol bound.
    #[error("shared-vault key wrap exceeds {MAX_SHARED_VAULT_KEY_BYTES} bytes")]
    VaultKeyTooLarge,
    /// A vault with this identifier already exists or another schema constraint was violated.
    #[error("sync storage constraint failed: {0}")]
    Constraint(#[source] sqlx::Error),
    /// The write batch is empty.
    #[error("sync write batch must not be empty")]
    EmptyBatch,
    /// The write batch exceeds the protocol object count limit.
    #[error("sync write batch exceeds {MAX_BATCH_OBJECTS} objects")]
    BatchObjectLimit,
    /// The write batch exceeds the protocol byte limit.
    #[error("sync write batch exceeds {MAX_BATCH_BYTES} bytes")]
    BatchByteLimit,
    /// An envelope exceeds the protocol envelope limit or is empty.
    #[error("sync envelope must contain between 1 and {MAX_ENVELOPE_BYTES} bytes")]
    InvalidEnvelope,
    /// The batch contains an object more than once.
    #[error("sync write batch contains a duplicate object id")]
    DuplicateObject,
    /// One or more object bases no longer match the current state.
    #[error("sync compare-and-swap conflict")]
    Conflict { conflicts: Vec<ConflictEntry> },
    /// A sequence cannot be represented by SQLite's signed integer column.
    #[error("sync sequence is exhausted")]
    SequenceExhausted,
    /// A caller supplied a cursor before the purge horizon.
    #[error("sync cursor is below the purge horizon ({purge_horizon})")]
    CursorExpired { purge_horizon: u64 },
    /// A caller supplied a cursor after the vault's current sequence.
    #[error("sync cursor {cursor} is ahead of the current sequence {current}")]
    CursorAhead { cursor: u64, current: u64 },
    /// A change page size was outside the protocol range.
    #[error("sync page size must be between 1 and {MAX_PAGE_SIZE}")]
    InvalidPageSize,
    /// The requested object has no current or retained version.
    #[error("sync object does not exist")]
    ObjectNotFound,
    /// A retention pass was supplied a negative timestamp.
    #[error("sync retention timestamp must not be negative")]
    InvalidRetentionTime,
    /// A stored row could not be represented by the public storage model.
    #[error("sync storage contains invalid row data: {0}")]
    CorruptRow(&'static str),
    /// The database operation failed.
    #[error("sync database error: {0}")]
    Database(#[from] sqlx::Error),
    /// A durable sync cardinality limit would be exceeded.
    #[error("sync {0} quota would be exceeded")]
    QuotaExceeded(&'static str),
}

impl SqliteStore {
    /// List owned personal and current shared vaults in stable vault-id order.
    ///
    /// The account id must come from an authenticated device, never from a request body.
    ///
    /// # Errors
    ///
    /// Returns a database or corrupt-row error if metadata cannot be read safely.
    pub async fn list_sync_vaults_for_account(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<AccountVaultDescriptor>, SyncStoreError> {
        let rows = sqlx::query(
            "SELECT v.vault_id, v.kind, v.current_seq, p.key_epoch, v.rotation_pending
             FROM sync_personal_vaults AS p
             JOIN sync_vaults AS v ON v.vault_id = p.vault_id
             WHERE p.account_id = ? AND v.kind = 'personal'
             UNION ALL
             SELECT v.vault_id, v.kind, v.current_seq, m.key_epoch, v.rotation_pending
             FROM sync_vault_members AS m
             JOIN sync_vaults AS v ON v.vault_id = m.vault_id
             WHERE m.account_id = ? AND v.kind = 'shared'
             ORDER BY 1 ASC",
        )
        .bind(account_id.as_slice())
        .bind(account_id.as_slice())
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| {
                let kind = match row.try_get::<&str, _>("kind")? {
                    "personal" => VaultKind::Personal,
                    "shared" => VaultKind::Shared,
                    _ => return Err(SyncStoreError::CorruptRow("kind")),
                };
                Ok(AccountVaultDescriptor {
                    vault_id: id_from_bytes(&row.try_get::<Vec<u8>, _>("vault_id")?, "vault_id")?,
                    kind,
                    sequence: sequence_from_sql(row.try_get("current_seq")?)?,
                    key_epoch: epoch_from_sql(row.try_get("key_epoch")?)?,
                    rotation_pending: bool_from_sql(row.try_get("rotation_pending")?)?,
                })
            })
            .collect()
    }

    /// List a bounded, stable page of vault identifiers for retention scheduling.
    ///
    /// The worker deliberately receives identifiers only; membership and acknowledgement policy
    /// stay outside this storage enumeration. Callers repeat the bounded pass on later heartbeats.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::InvalidPageSize`] for an invalid bound or a database/corrupt-row
    /// error when vault identifiers cannot be read safely.
    pub async fn list_sync_vault_ids(&self, limit: u16) -> Result<Vec<VaultId>, SyncStoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(SyncStoreError::InvalidPageSize);
        }
        let rows = sqlx::query("SELECT vault_id FROM sync_vaults ORDER BY vault_id ASC LIMIT ?")
            .bind(i64::from(limit))
            .fetch_all(self.pool())
            .await?;
        rows.into_iter()
            .map(|row| id_from_bytes(&row.try_get::<Vec<u8>, _>("vault_id")?, "vault_id"))
            .collect()
    }

    /// Atomically provision one personal vault and its ARK-wrapped epoch-one key for an account.
    ///
    /// The identity enrollment service supplies the authenticated account and a client-generated
    /// `UUIDv7` vault id after validating the opaque key wrap. The unique account constraint makes
    /// concurrent enrollment safe; a second attempt never creates another personal vault.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultAlreadyExists`] for an existing account or vault id,
    /// validation errors for an invalid wrap, or a storage error on failed persistence.
    pub async fn create_personal_sync_vault(
        &self,
        vault_id: VaultId,
        account_id: AccountId,
        wrapped_vault_key: &[u8],
    ) -> Result<(), SyncStoreError> {
        if wrapped_vault_key.is_empty() {
            return Err(SyncStoreError::EmptyVaultKey);
        }
        if wrapped_vault_key.len() > MAX_SHARED_VAULT_KEY_BYTES {
            return Err(SyncStoreError::VaultKeyTooLarge);
        }
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let exists =
            sqlx::query_scalar::<_, i64>("SELECT 1 FROM sync_personal_vaults WHERE account_id = ?")
                .bind(account_id.as_slice())
                .fetch_optional(&mut *transaction)
                .await?;
        if exists.is_some() {
            return Err(SyncStoreError::VaultAlreadyExists);
        }

        let exists = sqlx::query_scalar::<_, i64>("SELECT 1 FROM sync_vaults WHERE vault_id = ?")
            .bind(vault_id.as_slice())
            .fetch_optional(&mut *transaction)
            .await?;
        if exists.is_some() {
            return Err(SyncStoreError::VaultAlreadyExists);
        }
        sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES (?, 'personal')")
            .bind(vault_id.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(map_constraint)?;
        sqlx::query(
            "INSERT INTO sync_personal_vaults (account_id, vault_id, wrapped_vault_key)
             VALUES (?, ?, ?)",
        )
        .bind(account_id.as_slice())
        .bind(vault_id.as_slice())
        .bind(wrapped_vault_key)
        .execute(&mut *transaction)
        .await
        .map_err(map_constraint)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Read the ARK-wrapped personal vault key only for its owning account.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`] if the account owns no personal vault.
    pub async fn get_personal_sync_vault_key(
        &self,
        account_id: AccountId,
    ) -> Result<(VaultId, Vec<u8>), SyncStoreError> {
        let row = sqlx::query(
            "SELECT vault_id, wrapped_vault_key FROM sync_personal_vaults WHERE account_id = ?",
        )
        .bind(account_id.as_slice())
        .fetch_optional(self.pool())
        .await?
        .ok_or(SyncStoreError::VaultNotFound)?;
        let vault_id = id_from_bytes(&row.try_get::<Vec<u8>, _>("vault_id")?, "vault_id")?;
        let wrapped_key: Vec<u8> = row.try_get("wrapped_vault_key")?;
        if wrapped_key.is_empty() || wrapped_key.len() > MAX_SHARED_VAULT_KEY_BYTES {
            return Err(SyncStoreError::CorruptRow("wrapped_vault_key"));
        }
        Ok((vault_id, wrapped_key))
    }

    /// List shared vaults for a current account member in stable vault-id order.
    ///
    /// Removed members have no row and cannot see the vault or its rotation state. Personal
    /// vaults are listed separately by account ownership; organization vaults are still pending.
    ///
    /// # Errors
    ///
    /// Returns a database or corrupt-row error if metadata cannot be read safely.
    pub async fn list_shared_sync_vaults_for_account(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<SharedVaultDescriptor>, SyncStoreError> {
        let rows = sqlx::query(
            "SELECT v.vault_id, v.current_seq, m.key_epoch, v.rotation_pending
             FROM sync_vault_members AS m
             JOIN sync_vaults AS v ON v.vault_id = m.vault_id
             WHERE m.account_id = ? AND v.kind = 'shared'
             ORDER BY v.vault_id ASC",
        )
        .bind(account_id.as_slice())
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| {
                Ok(SharedVaultDescriptor {
                    vault_id: id_from_bytes(&row.try_get::<Vec<u8>, _>("vault_id")?, "vault_id")?,
                    sequence: sequence_from_sql(row.try_get("current_seq")?)?,
                    key_epoch: epoch_from_sql(row.try_get("key_epoch")?)?,
                    rotation_pending: bool_from_sql(row.try_get("rotation_pending")?)?,
                })
            })
            .collect()
    }

    /// Create an empty sync vault with sequence and purge horizon set to zero.
    ///
    /// This method does not perform account or membership authorization.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::Constraint`] when the identifier is already present or violates
    /// a database constraint, and [`SyncStoreError::Database`] for other database failures.
    pub async fn create_sync_vault(
        &self,
        vault_id: VaultId,
        kind: VaultKind,
    ) -> Result<(), SyncStoreError> {
        sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES (?, ?)")
            .bind(vault_id.as_slice())
            .bind(kind.as_str())
            .execute(self.pool())
            .await
            .map(|_| ())
            .map_err(|error| match error {
                sqlx::Error::Database(_) => SyncStoreError::Constraint(error),
                other => SyncStoreError::Database(other),
            })
    }

    /// Atomically create a shared vault and its initial admin/member key wrap.
    ///
    /// The account identifier is supplied by the authenticated service boundary. The store keeps
    /// the wrapped key opaque and records it at epoch one without decrypting it.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultAlreadyExists`] without changing state when the identifier
    /// is already present, validation errors for an invalid wrap, and a storage error when either
    /// row cannot be committed.
    pub async fn create_shared_sync_vault(
        &self,
        vault_id: VaultId,
        account_id: AccountId,
        wrapped_vault_key: &[u8],
    ) -> Result<(), SyncStoreError> {
        if wrapped_vault_key.is_empty() {
            return Err(SyncStoreError::EmptyVaultKey);
        }
        if wrapped_vault_key.len() > MAX_SHARED_VAULT_KEY_BYTES {
            return Err(SyncStoreError::VaultKeyTooLarge);
        }

        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        let exists = sqlx::query_scalar::<_, i64>("SELECT 1 FROM sync_vaults WHERE vault_id = ?")
            .bind(vault_id.as_slice())
            .fetch_optional(&mut *transaction)
            .await?;
        if exists.is_some() {
            return Err(SyncStoreError::VaultAlreadyExists);
        }

        let shared_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_vault_members AS m
             JOIN sync_vaults AS v ON v.vault_id = m.vault_id
             WHERE m.account_id = ? AND v.kind = 'shared'",
        )
        .bind(account_id.as_slice())
        .fetch_one(&mut *transaction)
        .await?;
        if u64::try_from(shared_count).map_err(|_| SyncStoreError::CorruptRow("shared_count"))?
            >= self.sync_cardinality_limits().max_shared_vaults_per_account
        {
            return Err(SyncStoreError::QuotaExceeded("shared vaults per account"));
        }

        sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES (?, 'shared')")
            .bind(vault_id.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(map_constraint)?;
        sqlx::query(
            "INSERT INTO sync_vault_members
             (vault_id, account_id, role, key_epoch, wrapped_vault_key)
             VALUES (?, ?, 'admin', 1, ?)",
        )
        .bind(vault_id.as_slice())
        .bind(account_id.as_slice())
        .bind(wrapped_vault_key)
        .execute(&mut *transaction)
        .await
        .map_err(map_constraint)?;
        sqlx::query(
            "INSERT INTO sync_vault_member_keys
             (vault_id, account_id, epoch, wrapped_vault_key)
             VALUES (?, ?, 1, ?)",
        )
        .bind(vault_id.as_slice())
        .bind(account_id.as_slice())
        .bind(wrapped_vault_key)
        .execute(&mut *transaction)
        .await
        .map_err(map_constraint)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Return the non-retired wrapped keys for one shared-vault member.
    ///
    /// The current creation boundary stores epoch one in the membership row. Future rotation
    /// migrations can add rows without changing this service-facing representation.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`] when the vault or account membership is absent,
    /// [`SyncStoreError::CorruptRow`] when a stored epoch or wrap violates its bounds, and
    /// [`SyncStoreError::Database`] when the lookup fails.
    pub async fn get_shared_sync_vault_keys(
        &self,
        vault_id: VaultId,
        account_id: AccountId,
    ) -> Result<Vec<SharedVaultKey>, SyncStoreError> {
        let rows = sqlx::query(
            "SELECT epoch, wrapped_vault_key FROM sync_vault_member_keys
             WHERE vault_id = ? AND account_id = ?
               AND NOT EXISTS (
                 SELECT 1 FROM sync_vault_retired_epochs AS r
                 WHERE r.vault_id = sync_vault_member_keys.vault_id AND r.epoch = sync_vault_member_keys.epoch
               )
             ORDER BY epoch ASC",
        )
        .bind(vault_id.as_slice())
        .bind(account_id.as_slice())
        .fetch_all(self.pool())
        .await?;
        if rows.is_empty() {
            return Err(SyncStoreError::VaultNotFound);
        }
        rows.into_iter()
            .map(|row| {
                let epoch = epoch_from_sql(row.try_get("epoch")?)?;
                let wrapped_vault_key: Vec<u8> = row.try_get("wrapped_vault_key")?;
                if wrapped_vault_key.is_empty()
                    || wrapped_vault_key.len() > MAX_SHARED_VAULT_KEY_BYTES
                {
                    return Err(SyncStoreError::CorruptRow("wrapped_vault_key"));
                }
                Ok(SharedVaultKey { epoch, wrapped_vault_key })
            })
            .collect()
    }

    /// Atomically publish the next shared-vault epoch for every current member.
    ///
    /// # Errors
    ///
    /// Returns a conflict when the epoch is not the next value, a member-set error when the
    /// supplied wraps do not exactly match current members, a key-response limit error when the
    /// next epoch would exceed the wire bounds, validation errors for malformed wraps, and a
    /// storage error when the transaction cannot commit.
    pub async fn publish_shared_sync_vault_epoch(
        &self,
        vault_id: VaultId,
        epoch: u64,
        wraps: &[SharedVaultEpochWrap],
    ) -> Result<(), SyncStoreError> {
        validate_epoch_wraps(wraps)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        lock_vault(&mut transaction, vault_id).await?;
        let current_epoch = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT MAX(k.epoch) FROM sync_vault_member_keys AS k
             WHERE k.vault_id = ? AND NOT EXISTS (
               SELECT 1 FROM sync_vault_retired_epochs AS r
               WHERE r.vault_id = k.vault_id AND r.epoch = k.epoch
             )",
        )
        .bind(vault_id.as_slice())
        .fetch_one(&mut *transaction)
        .await?
        .map(epoch_from_sql)
        .transpose()?
        .unwrap_or(0);
        let expected = current_epoch.checked_add(1).ok_or(SyncStoreError::SequenceExhausted)?;
        if epoch != expected {
            return Err(SyncStoreError::EpochConflict { current_epoch });
        }
        let member_rows = sqlx::query(
            "SELECT account_id FROM sync_vault_members WHERE vault_id = ? ORDER BY account_id ASC",
        )
        .bind(vault_id.as_slice())
        .fetch_all(&mut *transaction)
        .await?;
        let members = member_rows
            .iter()
            .map(|row| {
                let bytes: Vec<u8> = row.try_get("account_id")?;
                id_from_bytes(&bytes, "account_id")
            })
            .collect::<Result<Vec<_>, SyncStoreError>>()?;
        let supplied: Vec<AccountId> = wraps.iter().map(|wrap| wrap.account_id).collect();
        if supplied != members {
            return Err(SyncStoreError::MemberSetMismatch);
        }
        check_epoch_key_response_capacity(&mut transaction, vault_id, epoch, wraps).await?;
        for wrap in wraps {
            sqlx::query(
                "INSERT INTO sync_vault_member_keys
                 (vault_id, account_id, epoch, wrapped_vault_key) VALUES (?, ?, ?, ?)",
            )
            .bind(vault_id.as_slice())
            .bind(wrap.account_id.as_slice())
            .bind(sequence_to_sql(epoch)?)
            .bind(&wrap.wrapped_vault_key)
            .execute(&mut *transaction)
            .await
            .map_err(map_constraint)?;
            sqlx::query(
                "UPDATE sync_vault_members SET key_epoch = ?, wrapped_vault_key = ?
                 WHERE vault_id = ? AND account_id = ?",
            )
            .bind(sequence_to_sql(epoch)?)
            .bind(&wrap.wrapped_vault_key)
            .bind(vault_id.as_slice())
            .bind(wrap.account_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        }
        sqlx::query("UPDATE sync_vaults SET rotation_pending = 0 WHERE vault_id = ?")
            .bind(vault_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically add a member with one opaque wrap for every currently served epoch.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::MemberAlreadyExists`] for an existing member,
    /// [`SyncStoreError::MemberEpochMismatch`] when the epoch list is not exact,
    /// [`SyncStoreError::VaultKeyResponseLimit`] when its key response would exceed the wire
    /// bounds, validation errors for malformed wraps, and a storage error when the transaction
    /// cannot commit.
    pub async fn add_shared_sync_vault_member(
        &self,
        vault_id: VaultId,
        account_id: AccountId,
        wraps: &[SharedVaultKey],
    ) -> Result<(), SyncStoreError> {
        validate_member_wraps(wraps)?;
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        lock_vault(&mut transaction, vault_id).await?;
        let exists = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM sync_vault_members WHERE vault_id = ? AND account_id = ?",
        )
        .bind(vault_id.as_slice())
        .bind(account_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?;
        if exists.is_some() {
            return Err(SyncStoreError::MemberAlreadyExists);
        }
        let member_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = ?",
        )
        .bind(vault_id.as_slice())
        .fetch_one(&mut *transaction)
        .await?;
        if u64::try_from(member_count).map_err(|_| SyncStoreError::CorruptRow("member_count"))?
            >= self.sync_cardinality_limits().max_members_per_shared_vault
        {
            return Err(SyncStoreError::QuotaExceeded("members per shared vault"));
        }
        let shared_count = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_vault_members AS m
             JOIN sync_vaults AS v ON v.vault_id = m.vault_id
             WHERE m.account_id = ? AND v.kind = 'shared'",
        )
        .bind(account_id.as_slice())
        .fetch_one(&mut *transaction)
        .await?;
        if u64::try_from(shared_count).map_err(|_| SyncStoreError::CorruptRow("shared_count"))?
            >= self.sync_cardinality_limits().max_shared_vaults_per_account
        {
            return Err(SyncStoreError::QuotaExceeded("shared vaults per account"));
        }
        let epoch_rows = sqlx::query(
            "SELECT DISTINCT k.epoch FROM sync_vault_member_keys AS k
             WHERE k.vault_id = ? AND NOT EXISTS (
               SELECT 1 FROM sync_vault_retired_epochs AS r
               WHERE r.vault_id = k.vault_id AND r.epoch = k.epoch
             )
             ORDER BY k.epoch ASC",
        )
        .bind(vault_id.as_slice())
        .fetch_all(&mut *transaction)
        .await?;
        let epochs = epoch_rows
            .iter()
            .map(|row| epoch_from_sql(row.try_get("epoch")?))
            .collect::<Result<Vec<_>, SyncStoreError>>()?;
        let supplied_epochs: Vec<u64> = wraps.iter().map(|wrap| wrap.epoch).collect();
        if supplied_epochs != epochs {
            return Err(SyncStoreError::MemberEpochMismatch);
        }
        if vault_keys_response_bytes(
            wraps.iter().map(|wrap| (wrap.epoch, wrap.wrapped_vault_key.len())),
            wraps.len(),
        ) > MAX_SHARED_VAULT_KEYS_BODY_BYTES
        {
            return Err(SyncStoreError::VaultKeyResponseLimit);
        }
        let current = wraps.last().ok_or(SyncStoreError::InvalidMemberWraps)?;
        sqlx::query(
            "INSERT INTO sync_vault_members
             (vault_id, account_id, role, key_epoch, wrapped_vault_key)
             VALUES (?, ?, 'member', ?, ?)",
        )
        .bind(vault_id.as_slice())
        .bind(account_id.as_slice())
        .bind(sequence_to_sql(current.epoch)?)
        .bind(&current.wrapped_vault_key)
        .execute(&mut *transaction)
        .await
        .map_err(map_constraint)?;
        for wrap in wraps {
            sqlx::query(
                "INSERT INTO sync_vault_member_keys
                 (vault_id, account_id, epoch, wrapped_vault_key) VALUES (?, ?, ?, ?)",
            )
            .bind(vault_id.as_slice())
            .bind(account_id.as_slice())
            .bind(sequence_to_sql(wrap.epoch)?)
            .bind(&wrap.wrapped_vault_key)
            .execute(&mut *transaction)
            .await
            .map_err(map_constraint)?;
        }
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically retire a previously served shared-vault epoch after re-encryption.
    ///
    /// Retirement is idempotent. The newest served epoch and epochs referenced by current
    /// objects remain available until a newer epoch is published and all objects are rewritten.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::EpochNotFound`] for an unknown epoch,
    /// [`SyncStoreError::EpochNewest`] for the newest served epoch,
    /// [`SyncStoreError::EpochInUse`] when current objects still reference it, and
    /// [`SyncStoreError::UnsupportedVaultKind`] for personal or organization vaults.
    pub async fn retire_shared_sync_vault_epoch(
        &self,
        vault_id: VaultId,
        epoch: u64,
    ) -> Result<(), SyncStoreError> {
        if epoch == 0 {
            return Err(SyncStoreError::EpochNotFound { epoch });
        }
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        lock_vault(&mut transaction, vault_id).await?;
        let kind =
            sqlx::query_scalar::<_, String>("SELECT kind FROM sync_vaults WHERE vault_id = ?")
                .bind(vault_id.as_slice())
                .fetch_one(&mut *transaction)
                .await?;
        if kind != "shared" {
            return Err(SyncStoreError::UnsupportedVaultKind);
        }
        let already_retired = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM sync_vault_retired_epochs WHERE vault_id = ? AND epoch = ?",
        )
        .bind(vault_id.as_slice())
        .bind(sequence_to_sql(epoch)?)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if already_retired {
            transaction.commit().await?;
            return Ok(());
        }
        let served = sqlx::query_scalar::<_, i64>(
            "SELECT 1 FROM sync_vault_member_keys AS k
             WHERE k.vault_id = ? AND k.epoch = ?
               AND NOT EXISTS (
                 SELECT 1 FROM sync_vault_retired_epochs AS r
                 WHERE r.vault_id = k.vault_id AND r.epoch = k.epoch
               )
             LIMIT 1",
        )
        .bind(vault_id.as_slice())
        .bind(sequence_to_sql(epoch)?)
        .fetch_optional(&mut *transaction)
        .await?
        .is_some();
        if !served {
            return Err(SyncStoreError::EpochNotFound { epoch });
        }
        let newest = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT MAX(k.epoch) FROM sync_vault_member_keys AS k
             WHERE k.vault_id = ? AND NOT EXISTS (
               SELECT 1 FROM sync_vault_retired_epochs AS r
               WHERE r.vault_id = k.vault_id AND r.epoch = k.epoch
             )",
        )
        .bind(vault_id.as_slice())
        .fetch_one(&mut *transaction)
        .await?
        .map(epoch_from_sql)
        .transpose()?
        .ok_or(SyncStoreError::EpochNotFound { epoch })?;
        if epoch == newest {
            return Err(SyncStoreError::EpochNewest { epoch });
        }
        let references = sqlx::query_scalar::<_, i64>(
            "SELECT COUNT(*) FROM sync_objects WHERE vault_id = ? AND key_epoch = ?",
        )
        .bind(vault_id.as_slice())
        .bind(sequence_to_sql(epoch)?)
        .fetch_one(&mut *transaction)
        .await?;
        if references != 0 {
            return Err(SyncStoreError::EpochInUse { epoch });
        }
        sqlx::query("DELETE FROM sync_vault_member_keys WHERE vault_id = ? AND epoch = ?")
            .bind(vault_id.as_slice())
            .bind(sequence_to_sql(epoch)?)
            .execute(&mut *transaction)
            .await?;
        sqlx::query("INSERT INTO sync_vault_retired_epochs (vault_id, epoch) VALUES (?, ?)")
            .bind(vault_id.as_slice())
            .bind(sequence_to_sql(epoch)?)
            .execute(&mut *transaction)
            .await
            .map_err(map_constraint)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Atomically remove a shared-vault member and mark the vault for re-keying.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::MemberNotFound`] when the account is not a current member,
    /// [`SyncStoreError::LastAdmin`] when removal would leave no admin, and a storage error when
    /// the membership, historical wraps, or pending marker cannot be committed together.
    pub async fn remove_shared_sync_vault_member(
        &self,
        vault_id: VaultId,
        account_id: AccountId,
    ) -> Result<(), SyncStoreError> {
        let mut transaction = self.pool().begin_with("BEGIN IMMEDIATE").await?;
        lock_vault(&mut transaction, vault_id).await?;
        let role = sqlx::query_scalar::<_, String>(
            "SELECT role FROM sync_vault_members WHERE vault_id = ? AND account_id = ?",
        )
        .bind(vault_id.as_slice())
        .bind(account_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .ok_or(SyncStoreError::MemberNotFound)?;
        if role == "admin" {
            let admin_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sync_vault_members WHERE vault_id = ? AND role = 'admin'",
            )
            .bind(vault_id.as_slice())
            .fetch_one(&mut *transaction)
            .await?;
            if admin_count <= 1 {
                return Err(SyncStoreError::LastAdmin);
            }
        }
        let deleted =
            sqlx::query("DELETE FROM sync_vault_members WHERE vault_id = ? AND account_id = ?")
                .bind(vault_id.as_slice())
                .bind(account_id.as_slice())
                .execute(&mut *transaction)
                .await?;
        if deleted.rows_affected() != 1 {
            return Err(SyncStoreError::MemberNotFound);
        }
        sqlx::query("UPDATE sync_vaults SET rotation_pending = 1 WHERE vault_id = ?")
            .bind(vault_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(())
    }

    /// Return the kind of one sync vault for service-level authorization checks.
    ///
    /// # Errors
    ///
    /// Returns `SyncStoreError::VaultNotFound` when the vault does not exist or
    /// `SyncStoreError::Database` when the metadata cannot be read.
    pub async fn sync_vault_kind(&self, vault_id: VaultId) -> Result<VaultKind, SyncStoreError> {
        let kind =
            sqlx::query_scalar::<_, String>("SELECT kind FROM sync_vaults WHERE vault_id = ?")
                .bind(vault_id.as_slice())
                .fetch_optional(self.pool())
                .await?
                .ok_or(SyncStoreError::VaultNotFound)?;
        match kind.as_str() {
            "personal" => Ok(VaultKind::Personal),
            "shared" => Ok(VaultKind::Shared),
            "organization" => Ok(VaultKind::Organization),
            _ => Err(SyncStoreError::CorruptRow("kind")),
        }
    }

    /// Write one authenticated batch atomically using compare-and-swap bases.
    ///
    /// A write transaction first takes SQLite's write lock by updating the vault counter with a
    /// no-op. It then validates every base before allocating a contiguous sequence range. Any
    /// conflict or constraint failure rolls back the whole batch, including the counter.
    ///
    /// # Errors
    ///
    /// Returns a validation error for an invalid batch, [`SyncStoreError::Conflict`] when any
    /// compare-and-swap base is stale, or [`SyncStoreError::Database`] for a database failure.
    #[allow(clippy::too_many_lines)]
    pub async fn write_sync_batch(
        &self,
        vault_id: VaultId,
        writes: &[ObjectWrite],
    ) -> Result<Vec<WriteReceipt>, SyncStoreError> {
        validate_batch(writes)?;
        let mut transaction = self.pool().begin().await?;
        lock_vault(&mut transaction, vault_id).await?;
        let (current_seq, _) = vault_state(&mut transaction, vault_id).await?;
        for write in writes {
            let retired = sqlx::query_scalar::<_, i64>(
                "SELECT 1 FROM sync_vault_retired_epochs WHERE vault_id = ? AND epoch = ?",
            )
            .bind(vault_id.as_slice())
            .bind(sequence_to_sql(write.key_epoch)?)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
            if retired {
                return Err(SyncStoreError::EpochRetired { epoch: write.key_epoch });
            }
        }

        let mut current = HashMap::with_capacity(writes.len());
        for write in writes {
            let row = sqlx::query(
                "SELECT sequence, envelope, tombstone, signer_device_id, key_epoch FROM sync_objects \
                 WHERE vault_id = ? AND object_id = ?",
            )
            .bind(vault_id.as_slice())
            .bind(write.object_id.as_slice())
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(row) = row {
                current.insert(write.object_id, change_from_row(write.object_id, &row)?);
            }
        }

        let conflicts = writes
            .iter()
            .filter_map(|write| {
                let existing = current.get(&write.object_id);
                let matches = match (write.base_sequence, existing) {
                    (None, None) => true,
                    (Some(base), Some(change)) => base == change.sequence,
                    _ => false,
                };
                (!matches).then(|| ConflictEntry {
                    object_id: write.object_id,
                    current: existing.cloned(),
                })
            })
            .collect::<Vec<_>>();
        if !conflicts.is_empty() {
            return Err(SyncStoreError::Conflict { conflicts });
        }

        let new_objects = writes.len() - current.len();
        if new_objects > 0 {
            let object_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sync_objects WHERE vault_id = ?",
            )
            .bind(vault_id.as_slice())
            .fetch_one(&mut *transaction)
            .await?;
            let object_count = u64::try_from(object_count)
                .map_err(|_| SyncStoreError::CorruptRow("object_count"))?;
            let new_objects =
                u64::try_from(new_objects).map_err(|_| SyncStoreError::SequenceExhausted)?;
            if object_count
                .checked_add(new_objects)
                .is_none_or(|count| count > self.sync_cardinality_limits().max_objects_per_vault)
            {
                return Err(SyncStoreError::QuotaExceeded("objects per vault"));
            }
        }

        let batch_len =
            u64::try_from(writes.len()).map_err(|_| SyncStoreError::SequenceExhausted)?;
        let first_sequence = current_seq.checked_add(1).ok_or(SyncStoreError::SequenceExhausted)?;
        let last_sequence =
            current_seq.checked_add(batch_len).ok_or(SyncStoreError::SequenceExhausted)?;
        let mut receipts = Vec::with_capacity(writes.len());
        for (offset, write) in writes.iter().enumerate() {
            let offset = u64::try_from(offset).map_err(|_| SyncStoreError::SequenceExhausted)?;
            let sequence =
                first_sequence.checked_add(offset).ok_or(SyncStoreError::SequenceExhausted)?;
            let sequence_sql = sequence_to_sql(sequence)?;
            let written_at_ms = now_ms()?;
            let change = SyncChange {
                object_id: write.object_id,
                sequence,
                envelope: write.envelope.clone(),
                key_epoch: write.key_epoch,
                tombstone: write.tombstone,
                signer_device_id: write.signer_device_id,
            };
            insert_version(&mut transaction, vault_id, &change, written_at_ms).await?;
            sqlx::query(
                "INSERT INTO sync_objects \
                (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, key_epoch, written_at_ms) \
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?) \
                 ON CONFLICT (vault_id, object_id) DO UPDATE SET \
                   sequence = excluded.sequence, envelope = excluded.envelope, \
                   tombstone = excluded.tombstone, signer_device_id = excluded.signer_device_id, \
                   key_epoch = excluded.key_epoch, \
                   written_at_ms = excluded.written_at_ms",
            )
            .bind(vault_id.as_slice())
            .bind(write.object_id.as_slice())
            .bind(sequence_sql)
            .bind(&write.envelope)
            .bind(i64::from(write.tombstone))
            .bind(write.signer_device_id.as_ref().map(<DeviceId>::as_slice))
            .bind(sequence_to_sql(write.key_epoch)?)
            .bind(written_at_ms)
            .execute(&mut *transaction)
            .await?;
            receipts.push(WriteReceipt { object_id: write.object_id, sequence });
        }
        sqlx::query("UPDATE sync_vaults SET current_seq = ? WHERE vault_id = ?")
            .bind(sequence_to_sql(last_sequence)?)
            .bind(vault_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(receipts)
    }

    /// Read current object versions after a cursor at one consistent vault snapshot.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`], [`SyncStoreError::CursorExpired`],
    /// [`SyncStoreError::CursorAhead`], [`SyncStoreError::InvalidPageSize`], or
    /// [`SyncStoreError::Database`] when the request cannot be served.
    pub async fn sync_changes(
        &self,
        vault_id: VaultId,
        after: u64,
        limit: u16,
    ) -> Result<ChangePage, SyncStoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(SyncStoreError::InvalidPageSize);
        }
        let mut transaction = self.pool().begin().await?;
        let page = read_current_page(&mut transaction, vault_id, after, limit, true).await?;
        transaction.commit().await?;
        Ok(page)
    }

    /// Read a full-reconciliation page of current object versions.
    ///
    /// Snapshot paging uses the same ordering and cursor bounds as the change feed, but permits
    /// `after = 0` after purging so a client with an expired cursor can rebuild complete state.
    /// This is a storage operation; authorization and policy filtering remain service concerns.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`], [`SyncStoreError::CursorAhead`],
    /// [`SyncStoreError::InvalidPageSize`], or [`SyncStoreError::Database`] when the request
    /// cannot be served.
    pub async fn sync_snapshot(
        &self,
        vault_id: VaultId,
        after: u64,
        limit: u16,
    ) -> Result<SnapshotPage, SyncStoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(SyncStoreError::InvalidPageSize);
        }
        let mut transaction = self.pool().begin().await?;
        let page = read_current_page(&mut transaction, vault_id, after, limit, false).await?;
        transaction.commit().await?;
        Ok(SnapshotPage { objects: page.changes, next_cursor: page.next_cursor, more: page.more })
    }

    /// Read the current version and retained history for one object in ascending sequence order.
    /// At most the current version and 20 retained previous versions are returned.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`] for an unknown vault,
    /// [`SyncStoreError::ObjectNotFound`] when no version exists, or
    /// [`SyncStoreError::Database`] when the history cannot be read.
    pub async fn sync_versions(
        &self,
        vault_id: VaultId,
        object_id: ObjectId,
    ) -> Result<Vec<SyncChange>, SyncStoreError> {
        let mut transaction = self.pool().begin().await?;
        vault_state(&mut transaction, vault_id).await?;
        let rows = sqlx::query(
            "SELECT sequence, envelope, tombstone, signer_device_id, key_epoch \
             FROM sync_object_versions WHERE vault_id = ? AND object_id = ? \
             ORDER BY sequence DESC LIMIT 21",
        )
        .bind(vault_id.as_slice())
        .bind(object_id.as_slice())
        .fetch_all(&mut *transaction)
        .await?;
        if rows.is_empty() {
            return Err(SyncStoreError::ObjectNotFound);
        }
        let mut versions = rows
            .iter()
            .map(|row| change_from_row(object_id, row))
            .collect::<Result<Vec<_>, SyncStoreError>>()?;
        versions.reverse();
        transaction.commit().await?;
        Ok(versions)
    }

    /// Record a device cursor after the client has applied changes.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`] for an unknown vault, [`SyncStoreError::CursorAhead`]
    /// for a cursor beyond the vault, or [`SyncStoreError::Database`] when the acknowledgement
    /// cannot be stored. A cursor at or below the stored value is an idempotent no-op and returns
    /// that stored value.
    pub async fn ack_sync_cursor(
        &self,
        vault_id: VaultId,
        device_id: DeviceId,
        cursor: u64,
    ) -> Result<u64, SyncStoreError> {
        let mut transaction = self.pool().begin().await?;
        lock_vault(&mut transaction, vault_id).await?;
        let (current_seq, _) = vault_state(&mut transaction, vault_id).await?;
        if cursor > current_seq {
            return Err(SyncStoreError::CursorAhead { cursor, current: current_seq });
        }
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT cursor FROM sync_acks WHERE vault_id = ? AND device_id = ?",
        )
        .bind(vault_id.as_slice())
        .bind(device_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .map(sequence_from_sql)
        .transpose()?;
        if let Some(existing) = existing
            && cursor <= existing
        {
            transaction.commit().await?;
            return Ok(existing);
        }
        sqlx::query(
            "INSERT INTO sync_acks (vault_id, device_id, cursor, acknowledged_at_ms) VALUES (?, ?, ?, ?) \
             ON CONFLICT (vault_id, device_id) DO UPDATE SET cursor = excluded.cursor, acknowledged_at_ms = excluded.acknowledged_at_ms",
        )
        .bind(vault_id.as_slice())
        .bind(device_id.as_slice())
        .bind(sequence_to_sql(cursor)?)
        .bind(now_ms()?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(cursor)
    }

    /// Prune old versions and purge eligible tombstones for one vault.
    ///
    /// The caller supplies the minimum acknowledgement cursor across every enrolled, unrevoked
    /// device that can access the vault. Passing `None` disables acknowledgement-based tombstone
    /// purging; the 180-day time limit still applies. This keeps membership and policy decisions
    /// outside the storage layer while giving the worker an atomic retention operation.
    ///
    /// Historical rows older than the newest current version plus 20 retained versions are
    /// removed. Tombstones are removed, together with all their retained versions, when their
    /// sequence is at or below the supplied acknowledgement floor or their current row is at
    /// least 180 days old. The purge horizon advances to the greatest sequence removed and never
    /// moves backwards.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`], [`SyncStoreError::CursorAhead`] when the
    /// supplied acknowledgement floor exceeds the vault sequence, [`SyncStoreError::InvalidRetentionTime`]
    /// for a negative timestamp, or [`SyncStoreError::Database`] for a database failure.
    pub async fn purge_sync_history(
        &self,
        vault_id: VaultId,
        acknowledged_through: Option<u64>,
        now_ms: i64,
    ) -> Result<PurgeReport, SyncStoreError> {
        if now_ms < 0 {
            return Err(SyncStoreError::InvalidRetentionTime);
        }
        let mut transaction = self.pool().begin().await?;
        lock_vault(&mut transaction, vault_id).await?;
        let (current_seq, existing_horizon) = vault_state(&mut transaction, vault_id).await?;
        if let Some(cursor) = acknowledged_through
            && cursor > current_seq
        {
            return Err(SyncStoreError::CursorAhead { cursor, current: current_seq });
        }

        let mut highest_removed = existing_horizon;
        let mut pruned_versions = 0_u64;
        let version_cutoff_ms = now_ms.saturating_sub(VERSION_RETENTION_DAYS * MILLIS_PER_DAY);
        let tombstone_cutoff_ms =
            now_ms.saturating_sub(TOMBSTONE_PURGE_AFTER_DAYS * MILLIS_PER_DAY);

        let old_version_max = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT MAX(sequence) FROM (\
             SELECT sequence, written_at_ms, ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY sequence DESC) AS rank \
             FROM sync_object_versions WHERE vault_id = ? \
             ) WHERE rank > 21 OR (rank > 1 AND written_at_ms < ?)",
        )
        .bind(vault_id.as_slice())
        .bind(version_cutoff_ms)
        .fetch_one(&mut *transaction)
        .await?
        .map(sequence_from_sql)
        .transpose()?;
        if let Some(max_sequence) = old_version_max {
            highest_removed = highest_removed.max(max_sequence);
        }
        let old_versions_result = sqlx::query(
            "DELETE FROM sync_object_versions WHERE vault_id = ? AND sequence IN (\
             SELECT sequence FROM (\
               SELECT sequence, written_at_ms, ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY sequence DESC) AS rank \
               FROM sync_object_versions WHERE vault_id = ? \
             ) WHERE rank > 21 OR (rank > 1 AND written_at_ms < ?))",
        )
        .bind(vault_id.as_slice())
        .bind(vault_id.as_slice())
        .bind(version_cutoff_ms)
        .execute(&mut *transaction)
        .await?;
        pruned_versions = pruned_versions.saturating_add(old_versions_result.rows_affected());

        let mut tombstone_query = String::from(
            "SELECT object_id, sequence FROM sync_objects WHERE vault_id = ? AND tombstone = 1 AND written_at_ms <= ?",
        );
        if acknowledged_through.is_some() {
            tombstone_query.push_str(" OR (vault_id = ? AND tombstone = 1 AND sequence <= ?)");
        }
        let mut query =
            sqlx::query(&tombstone_query).bind(vault_id.as_slice()).bind(tombstone_cutoff_ms);
        if let Some(cursor) = acknowledged_through {
            query = query.bind(vault_id.as_slice()).bind(sequence_to_sql(cursor)?);
        }
        let tombstones = query.fetch_all(&mut *transaction).await?;
        let mut purged_tombstones = 0_u64;
        for row in tombstones {
            let object_id_bytes: Vec<u8> = row.try_get("object_id")?;
            let object_id = id_from_bytes(&object_id_bytes, "object_id")?;
            let tombstone_sequence = sequence_from_sql(row.try_get("sequence")?)?;
            highest_removed = highest_removed.max(tombstone_sequence);
            let history = sqlx::query(
                "DELETE FROM sync_object_versions WHERE vault_id = ? AND object_id = ?",
            )
            .bind(vault_id.as_slice())
            .bind(object_id.as_slice())
            .execute(&mut *transaction)
            .await?;
            pruned_versions = pruned_versions.saturating_add(history.rows_affected());
            sqlx::query("DELETE FROM sync_objects WHERE vault_id = ? AND object_id = ?")
                .bind(vault_id.as_slice())
                .bind(object_id.as_slice())
                .execute(&mut *transaction)
                .await?;
            purged_tombstones = purged_tombstones.saturating_add(1);
        }

        if highest_removed > existing_horizon {
            sqlx::query("UPDATE sync_vaults SET purge_horizon = ? WHERE vault_id = ?")
                .bind(sequence_to_sql(highest_removed)?)
                .bind(vault_id.as_slice())
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(PurgeReport { pruned_versions, purged_tombstones, purge_horizon: highest_removed })
    }
}

impl PostgresStore {
    /// Return the kind of one sync vault for service-level authorization checks.
    ///
    /// # Errors
    ///
    /// Returns `SyncStoreError::VaultNotFound` when the vault does not exist or a storage error
    /// when its metadata cannot be read.
    pub async fn sync_vault_kind(&self, vault_id: VaultId) -> Result<VaultKind, SyncStoreError> {
        let kind =
            sqlx::query_scalar::<_, String>("SELECT kind FROM sync_vaults WHERE vault_id = $1")
                .bind(vault_id.as_slice())
                .fetch_optional(self.pool())
                .await?
                .ok_or(SyncStoreError::VaultNotFound)?;
        match kind.as_str() {
            "personal" => Ok(VaultKind::Personal),
            "shared" => Ok(VaultKind::Shared),
            "organization" => Ok(VaultKind::Organization),
            _ => Err(SyncStoreError::CorruptRow("kind")),
        }
    }

    /// Write one authenticated batch atomically using compare-and-swap bases.
    ///
    /// The vault row lock serializes writers before conflict and quota checks. Rejected batches
    /// leave both current objects and the sequence counter unchanged.
    ///
    /// # Errors
    ///
    /// Returns validation, conflict, quota, or database errors without a partial write.
    #[allow(clippy::too_many_lines)]
    pub async fn write_sync_batch(
        &self,
        vault_id: VaultId,
        writes: &[ObjectWrite],
    ) -> Result<Vec<WriteReceipt>, SyncStoreError> {
        validate_batch(writes)?;
        let mut transaction = self.pool().begin().await?;
        lock_vault_postgres(&mut transaction, vault_id).await?;
        let (current_seq, _) = vault_state_postgres(&mut transaction, vault_id).await?;
        for write in writes {
            let retired = sqlx::query_scalar::<_, i64>(
                "SELECT 1::BIGINT FROM sync_vault_retired_epochs WHERE vault_id = $1 AND epoch = $2",
            )
            .bind(vault_id.as_slice())
            .bind(sequence_to_sql(write.key_epoch)?)
            .fetch_optional(&mut *transaction)
            .await?
            .is_some();
            if retired {
                return Err(SyncStoreError::EpochRetired { epoch: write.key_epoch });
            }
        }

        let mut current = HashMap::with_capacity(writes.len());
        for write in writes {
            let row = sqlx::query(
                "SELECT sequence, envelope, tombstone, signer_device_id, key_epoch
                 FROM sync_objects WHERE vault_id = $1 AND object_id = $2",
            )
            .bind(vault_id.as_slice())
            .bind(write.object_id.as_slice())
            .fetch_optional(&mut *transaction)
            .await?;
            if let Some(row) = row {
                current.insert(write.object_id, change_from_postgres_row(write.object_id, &row)?);
            }
        }

        let conflicts = writes
            .iter()
            .filter_map(|write| {
                let existing = current.get(&write.object_id);
                let matches = match (write.base_sequence, existing) {
                    (None, None) => true,
                    (Some(base), Some(change)) => base == change.sequence,
                    _ => false,
                };
                (!matches).then(|| ConflictEntry {
                    object_id: write.object_id,
                    current: existing.cloned(),
                })
            })
            .collect::<Vec<_>>();
        if !conflicts.is_empty() {
            return Err(SyncStoreError::Conflict { conflicts });
        }

        let new_objects = writes.len() - current.len();
        if new_objects > 0 {
            let object_count = sqlx::query_scalar::<_, i64>(
                "SELECT COUNT(*) FROM sync_objects WHERE vault_id = $1",
            )
            .bind(vault_id.as_slice())
            .fetch_one(&mut *transaction)
            .await?;
            let object_count = u64::try_from(object_count)
                .map_err(|_| SyncStoreError::CorruptRow("object_count"))?;
            let new_objects =
                u64::try_from(new_objects).map_err(|_| SyncStoreError::SequenceExhausted)?;
            if object_count
                .checked_add(new_objects)
                .is_none_or(|count| count > self.sync_cardinality_limits().max_objects_per_vault)
            {
                return Err(SyncStoreError::QuotaExceeded("objects per vault"));
            }
        }

        let batch_len =
            u64::try_from(writes.len()).map_err(|_| SyncStoreError::SequenceExhausted)?;
        let first_sequence = current_seq.checked_add(1).ok_or(SyncStoreError::SequenceExhausted)?;
        let last_sequence =
            current_seq.checked_add(batch_len).ok_or(SyncStoreError::SequenceExhausted)?;
        let mut receipts = Vec::with_capacity(writes.len());
        for (offset, write) in writes.iter().enumerate() {
            let offset = u64::try_from(offset).map_err(|_| SyncStoreError::SequenceExhausted)?;
            let sequence =
                first_sequence.checked_add(offset).ok_or(SyncStoreError::SequenceExhausted)?;
            let sequence_sql = sequence_to_sql(sequence)?;
            let written_at_ms = now_ms()?;
            let change = SyncChange {
                object_id: write.object_id,
                sequence,
                envelope: write.envelope.clone(),
                key_epoch: write.key_epoch,
                tombstone: write.tombstone,
                signer_device_id: write.signer_device_id,
            };
            insert_version_postgres(&mut transaction, vault_id, &change, written_at_ms).await?;
            sqlx::query(
                "INSERT INTO sync_objects
                 (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, key_epoch, written_at_ms)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
                 ON CONFLICT (vault_id, object_id) DO UPDATE SET
                   sequence = EXCLUDED.sequence, envelope = EXCLUDED.envelope,
                   tombstone = EXCLUDED.tombstone, signer_device_id = EXCLUDED.signer_device_id,
                   key_epoch = EXCLUDED.key_epoch, written_at_ms = EXCLUDED.written_at_ms",
            )
            .bind(vault_id.as_slice())
            .bind(write.object_id.as_slice())
            .bind(sequence_sql)
            .bind(&write.envelope)
            .bind(write.tombstone)
            .bind(write.signer_device_id.as_ref().map(<DeviceId>::as_slice))
            .bind(sequence_to_sql(write.key_epoch)?)
            .bind(written_at_ms)
            .execute(&mut *transaction)
            .await?;
            receipts.push(WriteReceipt { object_id: write.object_id, sequence });
        }
        sqlx::query("UPDATE sync_vaults SET current_seq = $1 WHERE vault_id = $2")
            .bind(sequence_to_sql(last_sequence)?)
            .bind(vault_id.as_slice())
            .execute(&mut *transaction)
            .await?;
        transaction.commit().await?;
        Ok(receipts)
    }

    /// Read current object versions after a cursor at one consistent vault snapshot.
    ///
    /// # Errors
    ///
    /// Returns vault, cursor, page-size, or database errors when the request cannot be served.
    pub async fn sync_changes(
        &self,
        vault_id: VaultId,
        after: u64,
        limit: u16,
    ) -> Result<ChangePage, SyncStoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(SyncStoreError::InvalidPageSize);
        }
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let page =
            read_current_page_postgres(&mut transaction, vault_id, after, limit, true).await?;
        transaction.commit().await?;
        Ok(page)
    }

    /// Read a full-reconciliation page of current object versions.
    ///
    /// The page uses the change-feed order and cursor bounds, but accepts `after = 0` even after
    /// retention has advanced the purge horizon. Authorization remains a service concern.
    ///
    /// # Errors
    ///
    /// Returns a missing-vault, ahead-cursor, page-size, or database error.
    pub async fn sync_snapshot(
        &self,
        vault_id: VaultId,
        after: u64,
        limit: u16,
    ) -> Result<SnapshotPage, SyncStoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(SyncStoreError::InvalidPageSize);
        }
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let page =
            read_current_page_postgres(&mut transaction, vault_id, after, limit, false).await?;
        transaction.commit().await?;
        Ok(SnapshotPage { objects: page.changes, next_cursor: page.next_cursor, more: page.more })
    }

    /// Read the latest current and retained object versions in ascending sequence order.
    ///
    /// At most 21 versions are returned. A read-only repeatable-read transaction keeps the vault
    /// existence check and the version rows in one snapshot during concurrent writes or purges.
    ///
    /// # Errors
    ///
    /// Returns a missing-vault, missing-object, or database error.
    pub async fn sync_versions(
        &self,
        vault_id: VaultId,
        object_id: ObjectId,
    ) -> Result<Vec<SyncChange>, SyncStoreError> {
        let mut transaction = self.pool().begin().await?;
        sqlx::query("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ, READ ONLY")
            .execute(&mut *transaction)
            .await?;
        let exists =
            sqlx::query_scalar::<_, i64>("SELECT 1::BIGINT FROM sync_vaults WHERE vault_id = $1")
                .bind(vault_id.as_slice())
                .fetch_optional(&mut *transaction)
                .await?
                .is_some();
        if !exists {
            return Err(SyncStoreError::VaultNotFound);
        }
        let rows = sqlx::query(
            "SELECT sequence, envelope, tombstone, signer_device_id, key_epoch
             FROM sync_object_versions WHERE vault_id = $1 AND object_id = $2
             ORDER BY sequence DESC LIMIT 21",
        )
        .bind(vault_id.as_slice())
        .bind(object_id.as_slice())
        .fetch_all(&mut *transaction)
        .await?;
        if rows.is_empty() {
            return Err(SyncStoreError::ObjectNotFound);
        }
        let mut versions = rows
            .iter()
            .map(|row| change_from_postgres_row(object_id, row))
            .collect::<Result<Vec<_>, SyncStoreError>>()?;
        versions.reverse();
        transaction.commit().await?;
        Ok(versions)
    }

    /// Record a device cursor after the client has applied changes.
    ///
    /// # Errors
    ///
    /// Returns a missing-vault or ahead-cursor error, or a database error when persistence fails.
    /// Lower cursors are idempotent no-ops returning the stored maximum.
    pub async fn ack_sync_cursor(
        &self,
        vault_id: VaultId,
        device_id: DeviceId,
        cursor: u64,
    ) -> Result<u64, SyncStoreError> {
        let mut transaction = self.pool().begin().await?;
        lock_vault_postgres(&mut transaction, vault_id).await?;
        let (current_seq, _) = vault_state_postgres(&mut transaction, vault_id).await?;
        if cursor > current_seq {
            return Err(SyncStoreError::CursorAhead { cursor, current: current_seq });
        }
        let existing = sqlx::query_scalar::<_, i64>(
            "SELECT cursor FROM sync_acks WHERE vault_id = $1 AND device_id = $2",
        )
        .bind(vault_id.as_slice())
        .bind(device_id.as_slice())
        .fetch_optional(&mut *transaction)
        .await?
        .map(sequence_from_sql)
        .transpose()?;
        if let Some(existing) = existing
            && cursor <= existing
        {
            transaction.commit().await?;
            return Ok(existing);
        }
        sqlx::query(
            "INSERT INTO sync_acks (vault_id, device_id, cursor, acknowledged_at_ms)
             VALUES ($1, $2, $3, $4)
             ON CONFLICT (vault_id, device_id) DO UPDATE SET
               cursor = EXCLUDED.cursor, acknowledged_at_ms = EXCLUDED.acknowledged_at_ms",
        )
        .bind(vault_id.as_slice())
        .bind(device_id.as_slice())
        .bind(sequence_to_sql(cursor)?)
        .bind(now_ms()?)
        .execute(&mut *transaction)
        .await?;
        transaction.commit().await?;
        Ok(cursor)
    }

    /// List owned personal and current shared vaults in stable vault-id order.
    ///
    /// The account id must come from an authenticated device, never from a request body.
    ///
    /// # Errors
    ///
    /// Returns a database or corrupt-row error if metadata cannot be read safely.
    pub async fn list_sync_vaults_for_account(
        &self,
        account_id: AccountId,
    ) -> Result<Vec<AccountVaultDescriptor>, SyncStoreError> {
        let rows = sqlx::query(
            "SELECT v.vault_id, v.kind, v.current_seq, p.key_epoch, v.rotation_pending
             FROM sync_personal_vaults AS p
             JOIN sync_vaults AS v ON v.vault_id = p.vault_id
             WHERE p.account_id = $1 AND v.kind = 'personal'
             UNION ALL
             SELECT v.vault_id, v.kind, v.current_seq, m.key_epoch, v.rotation_pending
             FROM sync_vault_members AS m
             JOIN sync_vaults AS v ON v.vault_id = m.vault_id
             WHERE m.account_id = $2 AND v.kind = 'shared'
             ORDER BY 1 ASC",
        )
        .bind(account_id.as_slice())
        .bind(account_id.as_slice())
        .fetch_all(self.pool())
        .await?;
        rows.into_iter()
            .map(|row| {
                let kind = match row.try_get::<&str, _>("kind")? {
                    "personal" => VaultKind::Personal,
                    "shared" => VaultKind::Shared,
                    _ => return Err(SyncStoreError::CorruptRow("kind")),
                };
                Ok(AccountVaultDescriptor {
                    vault_id: id_from_bytes(&row.try_get::<Vec<u8>, _>("vault_id")?, "vault_id")?,
                    kind,
                    sequence: sequence_from_sql(row.try_get("current_seq")?)?,
                    key_epoch: epoch_from_sql(row.try_get("key_epoch")?)?,
                    rotation_pending: row.try_get("rotation_pending")?,
                })
            })
            .collect()
    }

    /// Atomically provision one personal vault and its ARK-wrapped epoch-one key for an account.
    ///
    /// The account and client-generated vault id must be validated by the enrollment service.
    /// A duplicate account or vault id leaves no partial vault row.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultAlreadyExists`] for an existing account or vault id,
    /// validation errors for an invalid wrap, or a storage error on failed persistence.
    pub async fn create_personal_sync_vault(
        &self,
        vault_id: VaultId,
        account_id: AccountId,
        wrapped_vault_key: &[u8],
    ) -> Result<(), SyncStoreError> {
        if wrapped_vault_key.is_empty() {
            return Err(SyncStoreError::EmptyVaultKey);
        }
        if wrapped_vault_key.len() > MAX_SHARED_VAULT_KEY_BYTES {
            return Err(SyncStoreError::VaultKeyTooLarge);
        }
        let mut transaction = self.pool().begin().await?;
        sqlx::query("INSERT INTO sync_vaults (vault_id, kind) VALUES ($1, 'personal')")
            .bind(vault_id.as_slice())
            .execute(&mut *transaction)
            .await
            .map_err(map_personal_vault_insert_error)?;
        sqlx::query(
            "INSERT INTO sync_personal_vaults (account_id, vault_id, wrapped_vault_key)
             VALUES ($1, $2, $3)",
        )
        .bind(account_id.as_slice())
        .bind(vault_id.as_slice())
        .bind(wrapped_vault_key)
        .execute(&mut *transaction)
        .await
        .map_err(map_personal_vault_insert_error)?;
        transaction.commit().await?;
        Ok(())
    }

    /// Read the ARK-wrapped personal vault key only for its owning account.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`] if the account owns no personal vault.
    pub async fn get_personal_sync_vault_key(
        &self,
        account_id: AccountId,
    ) -> Result<(VaultId, Vec<u8>), SyncStoreError> {
        let row = sqlx::query(
            "SELECT vault_id, wrapped_vault_key FROM sync_personal_vaults WHERE account_id = $1",
        )
        .bind(account_id.as_slice())
        .fetch_optional(self.pool())
        .await?
        .ok_or(SyncStoreError::VaultNotFound)?;
        let vault_id = id_from_bytes(&row.try_get::<Vec<u8>, _>("vault_id")?, "vault_id")?;
        let wrapped_key: Vec<u8> = row.try_get("wrapped_vault_key")?;
        if wrapped_key.is_empty() || wrapped_key.len() > MAX_SHARED_VAULT_KEY_BYTES {
            return Err(SyncStoreError::CorruptRow("wrapped_vault_key"));
        }
        Ok((vault_id, wrapped_key))
    }

    /// List a bounded, stable page of vault identifiers for retention scheduling.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::InvalidPageSize`] for an invalid bound or a database/corrupt-row
    /// error when vault identifiers cannot be read safely.
    pub async fn list_sync_vault_ids(&self, limit: u16) -> Result<Vec<VaultId>, SyncStoreError> {
        if !(1..=MAX_PAGE_SIZE).contains(&limit) {
            return Err(SyncStoreError::InvalidPageSize);
        }
        let rows = sqlx::query("SELECT vault_id FROM sync_vaults ORDER BY vault_id ASC LIMIT $1")
            .bind(i64::from(limit))
            .fetch_all(self.pool())
            .await?;
        rows.into_iter()
            .map(|row| id_from_bytes(&row.try_get::<Vec<u8>, _>("vault_id")?, "vault_id"))
            .collect()
    }

    /// Prune old PostgreSQL versions and purge eligible tombstones for one vault.
    ///
    /// # Errors
    ///
    /// Returns [`SyncStoreError::VaultNotFound`], [`SyncStoreError::CursorAhead`],
    /// [`SyncStoreError::InvalidRetentionTime`], or a database error when retention cannot be
    /// committed.
    pub async fn purge_sync_history(
        &self,
        vault_id: VaultId,
        acknowledged_through: Option<u64>,
        now_ms: i64,
    ) -> Result<PurgeReport, SyncStoreError> {
        if now_ms < 0 {
            return Err(SyncStoreError::InvalidRetentionTime);
        }
        let mut transaction = self.pool().begin().await?;
        lock_vault_postgres(&mut transaction, vault_id).await?;
        let (current_seq, existing_horizon) =
            vault_state_postgres(&mut transaction, vault_id).await?;
        if let Some(cursor) = acknowledged_through
            && cursor > current_seq
        {
            return Err(SyncStoreError::CursorAhead { cursor, current: current_seq });
        }

        let mut highest_removed = existing_horizon;
        let version_cutoff_ms = now_ms.saturating_sub(VERSION_RETENTION_DAYS * MILLIS_PER_DAY);
        let tombstone_cutoff_ms =
            now_ms.saturating_sub(TOMBSTONE_PURGE_AFTER_DAYS * MILLIS_PER_DAY);
        let old_version_max = sqlx::query_scalar::<_, Option<i64>>(
            "SELECT MAX(sequence) FROM (
             SELECT sequence, written_at_ms, ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY sequence DESC) AS rank
             FROM sync_object_versions WHERE vault_id = $1
             ) AS retained WHERE rank > 21 OR (rank > 1 AND written_at_ms < $2)",
        )
        .bind(vault_id.as_slice())
        .bind(version_cutoff_ms)
        .fetch_one(&mut *transaction)
        .await?
        .map(sequence_from_sql)
        .transpose()?;
        if let Some(max_sequence) = old_version_max {
            highest_removed = highest_removed.max(max_sequence);
        }
        let old_versions_result = sqlx::query(
            "DELETE FROM sync_object_versions WHERE vault_id = $1 AND sequence IN (
             SELECT sequence FROM (
               SELECT sequence, written_at_ms, ROW_NUMBER() OVER (PARTITION BY object_id ORDER BY sequence DESC) AS rank
               FROM sync_object_versions WHERE vault_id = $2
             ) AS retained WHERE rank > 21 OR (rank > 1 AND written_at_ms < $3))",
        )
        .bind(vault_id.as_slice())
        .bind(vault_id.as_slice())
        .bind(version_cutoff_ms)
        .execute(&mut *transaction)
        .await?;
        let pruned_versions = old_versions_result.rows_affected();

        let mut tombstone_query = String::from(
            "SELECT object_id, sequence FROM sync_objects
             WHERE vault_id = $1 AND tombstone = TRUE AND written_at_ms <= $2",
        );
        if acknowledged_through.is_some() {
            tombstone_query.push_str(" OR (vault_id = $3 AND tombstone = TRUE AND sequence <= $4)");
        }
        let mut query =
            sqlx::query(&tombstone_query).bind(vault_id.as_slice()).bind(tombstone_cutoff_ms);
        if let Some(cursor) = acknowledged_through {
            query = query.bind(vault_id.as_slice()).bind(sequence_to_sql(cursor)?);
        }
        let tombstones = query.fetch_all(&mut *transaction).await?;
        let mut purged_tombstones = 0_u64;
        let mut pruned_versions = pruned_versions;
        for row in tombstones {
            let object_id = id_from_bytes(&row.try_get::<Vec<u8>, _>("object_id")?, "object_id")?;
            highest_removed = highest_removed.max(sequence_from_sql(row.try_get("sequence")?)?);
            let history = sqlx::query(
                "DELETE FROM sync_object_versions WHERE vault_id = $1 AND object_id = $2",
            )
            .bind(vault_id.as_slice())
            .bind(object_id.as_slice())
            .execute(&mut *transaction)
            .await?;
            pruned_versions = pruned_versions.saturating_add(history.rows_affected());
            sqlx::query("DELETE FROM sync_objects WHERE vault_id = $1 AND object_id = $2")
                .bind(vault_id.as_slice())
                .bind(object_id.as_slice())
                .execute(&mut *transaction)
                .await?;
            purged_tombstones = purged_tombstones.saturating_add(1);
        }
        if highest_removed > existing_horizon {
            sqlx::query("UPDATE sync_vaults SET purge_horizon = $1 WHERE vault_id = $2")
                .bind(sequence_to_sql(highest_removed)?)
                .bind(vault_id.as_slice())
                .execute(&mut *transaction)
                .await?;
        }
        transaction.commit().await?;
        Ok(PurgeReport { pruned_versions, purged_tombstones, purge_horizon: highest_removed })
    }
}

async fn read_current_page(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
    after: u64,
    limit: u16,
    enforce_purge_horizon: bool,
) -> Result<ChangePage, SyncStoreError> {
    let (current_seq, purge_horizon) = vault_state(transaction, vault_id).await?;
    if enforce_purge_horizon && after < purge_horizon {
        return Err(SyncStoreError::CursorExpired { purge_horizon });
    }
    if after > current_seq {
        return Err(SyncStoreError::CursorAhead { cursor: after, current: current_seq });
    }

    let rows = sqlx::query(
        "SELECT object_id, sequence, envelope, tombstone, signer_device_id, key_epoch \
         FROM sync_objects WHERE vault_id = ? AND sequence > ? \
         ORDER BY sequence ASC LIMIT ?",
    )
    .bind(vault_id.as_slice())
    .bind(sequence_to_sql(after)?)
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut **transaction)
    .await?;
    let more = rows.len() > usize::from(limit);
    let changes = rows
        .into_iter()
        .take(usize::from(limit))
        .map(|row| {
            let object_id_bytes: Vec<u8> = row.try_get("object_id")?;
            let object_id = id_from_bytes(&object_id_bytes, "object_id")?;
            change_from_row(object_id, &row)
        })
        .collect::<Result<Vec<_>, SyncStoreError>>()?;
    let next_cursor = changes
        .last()
        .map_or(current_seq, |change| if more { change.sequence } else { current_seq });
    Ok(ChangePage { changes, next_cursor, more })
}

async fn read_current_page_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    vault_id: VaultId,
    after: u64,
    limit: u16,
    enforce_purge_horizon: bool,
) -> Result<ChangePage, SyncStoreError> {
    let row = sqlx::query("SELECT current_seq, purge_horizon FROM sync_vaults WHERE vault_id = $1")
        .bind(vault_id.as_slice())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(SyncStoreError::VaultNotFound)?;
    let current_seq = sequence_from_sql(row.try_get("current_seq")?)?;
    let purge_horizon = sequence_from_sql(row.try_get("purge_horizon")?)?;
    if enforce_purge_horizon && after < purge_horizon {
        return Err(SyncStoreError::CursorExpired { purge_horizon });
    }
    if after > current_seq {
        return Err(SyncStoreError::CursorAhead { cursor: after, current: current_seq });
    }

    let rows = sqlx::query(
        "SELECT object_id, sequence, envelope, tombstone, signer_device_id, key_epoch
         FROM sync_objects WHERE vault_id = $1 AND sequence > $2
         ORDER BY sequence ASC LIMIT $3",
    )
    .bind(vault_id.as_slice())
    .bind(sequence_to_sql(after)?)
    .bind(i64::from(limit) + 1)
    .fetch_all(&mut **transaction)
    .await?;
    let more = rows.len() > usize::from(limit);
    let changes = rows
        .into_iter()
        .take(usize::from(limit))
        .map(|row| {
            let object_id_bytes: Vec<u8> = row.try_get("object_id")?;
            let object_id = id_from_bytes(&object_id_bytes, "object_id")?;
            change_from_postgres_row(object_id, &row)
        })
        .collect::<Result<Vec<_>, SyncStoreError>>()?;
    let next_cursor = changes
        .last()
        .map_or(current_seq, |change| if more { change.sequence } else { current_seq });
    Ok(ChangePage { changes, next_cursor, more })
}

async fn lock_vault(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
) -> Result<(), SyncStoreError> {
    let result = sqlx::query("UPDATE sync_vaults SET current_seq = current_seq WHERE vault_id = ?")
        .bind(vault_id.as_slice())
        .execute(&mut **transaction)
        .await?;
    if result.rows_affected() != 1 {
        return Err(SyncStoreError::VaultNotFound);
    }
    Ok(())
}

async fn vault_state(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
) -> Result<(u64, u64), SyncStoreError> {
    let row = sqlx::query("SELECT current_seq, purge_horizon FROM sync_vaults WHERE vault_id = ?")
        .bind(vault_id.as_slice())
        .fetch_optional(&mut **transaction)
        .await?
        .ok_or(SyncStoreError::VaultNotFound)?;
    Ok((
        sequence_from_sql(row.try_get("current_seq")?)?,
        sequence_from_sql(row.try_get("purge_horizon")?)?,
    ))
}

async fn lock_vault_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    vault_id: VaultId,
) -> Result<(), SyncStoreError> {
    let result =
        sqlx::query("UPDATE sync_vaults SET current_seq = current_seq WHERE vault_id = $1")
            .bind(vault_id.as_slice())
            .execute(&mut **transaction)
            .await?;
    if result.rows_affected() != 1 {
        return Err(SyncStoreError::VaultNotFound);
    }
    Ok(())
}

async fn vault_state_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    vault_id: VaultId,
) -> Result<(u64, u64), SyncStoreError> {
    let row = sqlx::query(
        "SELECT current_seq, purge_horizon FROM sync_vaults WHERE vault_id = $1 FOR UPDATE",
    )
    .bind(vault_id.as_slice())
    .fetch_optional(&mut **transaction)
    .await?
    .ok_or(SyncStoreError::VaultNotFound)?;
    Ok((
        sequence_from_sql(row.try_get("current_seq")?)?,
        sequence_from_sql(row.try_get("purge_horizon")?)?,
    ))
}

async fn insert_version(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
    change: &SyncChange,
    written_at_ms: i64,
) -> Result<(), SyncStoreError> {
    sqlx::query(
        "INSERT INTO sync_object_versions \
         (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, key_epoch, written_at_ms) \
         VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
    )
    .bind(vault_id.as_slice())
    .bind(change.object_id.as_slice())
    .bind(sequence_to_sql(change.sequence)?)
    .bind(&change.envelope)
    .bind(i64::from(change.tombstone))
    .bind(change.signer_device_id.as_ref().map(<DeviceId>::as_slice))
    .bind(sequence_to_sql(change.key_epoch)?)
    .bind(written_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

async fn insert_version_postgres(
    transaction: &mut Transaction<'_, Postgres>,
    vault_id: VaultId,
    change: &SyncChange,
    written_at_ms: i64,
) -> Result<(), SyncStoreError> {
    sqlx::query(
        "INSERT INTO sync_object_versions
         (vault_id, object_id, sequence, envelope, tombstone, signer_device_id, key_epoch, written_at_ms)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8)",
    )
    .bind(vault_id.as_slice())
    .bind(change.object_id.as_slice())
    .bind(sequence_to_sql(change.sequence)?)
    .bind(&change.envelope)
    .bind(change.tombstone)
    .bind(change.signer_device_id.as_ref().map(<DeviceId>::as_slice))
    .bind(sequence_to_sql(change.key_epoch)?)
    .bind(written_at_ms)
    .execute(&mut **transaction)
    .await?;
    Ok(())
}

fn validate_batch(writes: &[ObjectWrite]) -> Result<(), SyncStoreError> {
    if writes.is_empty() {
        return Err(SyncStoreError::EmptyBatch);
    }
    if writes.len() > MAX_BATCH_OBJECTS {
        return Err(SyncStoreError::BatchObjectLimit);
    }
    let mut ids = HashSet::with_capacity(writes.len());
    let mut total_bytes = 0_usize;
    for write in writes {
        if write.key_epoch == 0 {
            return Err(SyncStoreError::InvalidEnvelope);
        }
        if !ids.insert(write.object_id) {
            return Err(SyncStoreError::DuplicateObject);
        }
        if write.envelope.is_empty() || write.envelope.len() > MAX_ENVELOPE_BYTES {
            return Err(SyncStoreError::InvalidEnvelope);
        }
        total_bytes =
            total_bytes.checked_add(write.envelope.len()).ok_or(SyncStoreError::BatchByteLimit)?;
    }
    if total_bytes > MAX_BATCH_BYTES {
        return Err(SyncStoreError::BatchByteLimit);
    }
    Ok(())
}

fn validate_epoch_wraps(wraps: &[SharedVaultEpochWrap]) -> Result<(), SyncStoreError> {
    if wraps.is_empty() || wraps.len() > MAX_SHARED_VAULT_EPOCH_WRAPS {
        return Err(SyncStoreError::InvalidEpochWraps);
    }
    let mut previous = None;
    for wrap in wraps {
        if wrap.account_id == [0; 16]
            || wrap.wrapped_vault_key.is_empty()
            || wrap.wrapped_vault_key.len() > MAX_SHARED_VAULT_KEY_BYTES
        {
            return Err(SyncStoreError::InvalidEpochWraps);
        }
        if let Some(previous) = previous
            && wrap.account_id <= previous
        {
            return Err(SyncStoreError::InvalidEpochWraps);
        }
        previous = Some(wrap.account_id);
    }
    Ok(())
}

fn validate_member_wraps(wraps: &[SharedVaultKey]) -> Result<(), SyncStoreError> {
    if wraps.is_empty() || wraps.len() > MAX_SHARED_VAULT_MEMBER_EPOCHS {
        return Err(SyncStoreError::InvalidMemberWraps);
    }
    let mut previous = 0;
    for wrap in wraps {
        if wrap.epoch <= previous
            || wrap.wrapped_vault_key.is_empty()
            || wrap.wrapped_vault_key.len() > MAX_SHARED_VAULT_KEY_BYTES
        {
            return Err(SyncStoreError::InvalidMemberWraps);
        }
        previous = wrap.epoch;
    }
    Ok(())
}

async fn check_epoch_key_response_capacity(
    transaction: &mut Transaction<'_, Sqlite>,
    vault_id: VaultId,
    epoch: u64,
    wraps: &[SharedVaultEpochWrap],
) -> Result<(), SyncStoreError> {
    let rows = sqlx::query(
        "SELECT k.account_id, k.epoch, length(k.wrapped_vault_key) AS wrap_bytes
         FROM sync_vault_member_keys AS k
         JOIN sync_vault_members AS m
           ON m.vault_id = k.vault_id AND m.account_id = k.account_id
         WHERE k.vault_id = ? AND NOT EXISTS (
           SELECT 1 FROM sync_vault_retired_epochs AS r
           WHERE r.vault_id = k.vault_id AND r.epoch = k.epoch
         )",
    )
    .bind(vault_id.as_slice())
    .fetch_all(&mut **transaction)
    .await?;
    let mut member_keys = HashMap::<AccountId, Vec<(u64, usize)>>::new();
    let mut active_epochs = HashSet::new();
    for row in rows {
        let account_id = id_from_bytes(&row.try_get::<Vec<u8>, _>("account_id")?, "account_id")?;
        let served_epoch = epoch_from_sql(row.try_get("epoch")?)?;
        let wrap_bytes = usize::try_from(row.try_get::<i64, _>("wrap_bytes")?)
            .map_err(|_| SyncStoreError::CorruptRow("wrapped_vault_key"))?;
        if !(1..=MAX_SHARED_VAULT_KEY_BYTES).contains(&wrap_bytes) {
            return Err(SyncStoreError::CorruptRow("wrapped_vault_key"));
        }
        member_keys.entry(account_id).or_default().push((served_epoch, wrap_bytes));
        active_epochs.insert(served_epoch);
    }
    if active_epochs.len() >= MAX_SHARED_VAULT_KEY_EPOCHS {
        return Err(SyncStoreError::VaultKeyResponseLimit);
    }
    for wrap in wraps {
        let existing = member_keys.get(&wrap.account_id).map(Vec::as_slice).unwrap_or_default();
        let projected = vault_keys_response_bytes(
            existing.iter().copied().chain(std::iter::once((epoch, wrap.wrapped_vault_key.len()))),
            existing.len() + 1,
        );
        if projected > MAX_SHARED_VAULT_KEYS_BODY_BYTES {
            return Err(SyncStoreError::VaultKeyResponseLimit);
        }
    }
    Ok(())
}

fn vault_keys_response_bytes(keys: impl Iterator<Item = (u64, usize)>, count: usize) -> usize {
    // Deterministic CBOR for {"keys": [{"epoch": uint, "wrapped_vault_key": bstr}, ...]}.
    // The fixed map and text keys occupy 6 and 25 bytes respectively.
    6 + cbor_argument_bytes(count as u64)
        + keys
            .map(|(epoch, wrap_bytes)| {
                25 + cbor_argument_bytes(epoch)
                    + cbor_argument_bytes(wrap_bytes as u64)
                    + wrap_bytes
            })
            .sum::<usize>()
}

fn cbor_argument_bytes(value: u64) -> usize {
    match value {
        0..=23 => 1,
        24..=255 => 2,
        256..=65_535 => 3,
        65_536..=4_294_967_295 => 5,
        _ => 9,
    }
}

fn map_constraint(error: sqlx::Error) -> SyncStoreError {
    match error {
        sqlx::Error::Database(_) => SyncStoreError::Constraint(error),
        other => SyncStoreError::Database(other),
    }
}

fn map_personal_vault_insert_error(error: sqlx::Error) -> SyncStoreError {
    if error.as_database_error().and_then(sqlx::error::DatabaseError::code).as_deref()
        == Some("23505")
    {
        SyncStoreError::VaultAlreadyExists
    } else {
        map_constraint(error)
    }
}

fn change_from_row(
    object_id: ObjectId,
    row: &sqlx::sqlite::SqliteRow,
) -> Result<SyncChange, SyncStoreError> {
    Ok(SyncChange {
        object_id,
        sequence: sequence_from_sql(row.try_get("sequence")?)?,
        envelope: row.try_get("envelope")?,
        key_epoch: epoch_from_sql(row.try_get("key_epoch")?)?,
        tombstone: bool_from_sql(row.try_get("tombstone")?)?,
        signer_device_id: row
            .try_get::<Option<Vec<u8>>, _>("signer_device_id")?
            .map(|bytes| id_from_bytes(&bytes, "signer_device_id"))
            .transpose()?,
    })
}

fn change_from_postgres_row(
    object_id: ObjectId,
    row: &sqlx::postgres::PgRow,
) -> Result<SyncChange, SyncStoreError> {
    Ok(SyncChange {
        object_id,
        sequence: sequence_from_sql(row.try_get("sequence")?)?,
        envelope: row.try_get("envelope")?,
        key_epoch: epoch_from_sql(row.try_get("key_epoch")?)?,
        tombstone: row.try_get("tombstone")?,
        signer_device_id: row
            .try_get::<Option<Vec<u8>>, _>("signer_device_id")?
            .map(|bytes| id_from_bytes(&bytes, "signer_device_id"))
            .transpose()?,
    })
}

fn id_from_bytes(bytes: &[u8], field: &'static str) -> Result<[u8; 16], SyncStoreError> {
    bytes.try_into().map_err(|_| SyncStoreError::CorruptRow(field))
}

fn bool_from_sql(value: i64) -> Result<bool, SyncStoreError> {
    match value {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(SyncStoreError::CorruptRow("tombstone")),
    }
}

fn sequence_from_sql(value: i64) -> Result<u64, SyncStoreError> {
    value.try_into().map_err(|_| SyncStoreError::CorruptRow("sequence"))
}

fn epoch_from_sql(value: i64) -> Result<u64, SyncStoreError> {
    let epoch = value.try_into().map_err(|_| SyncStoreError::CorruptRow("key_epoch"))?;
    if epoch == 0 {
        return Err(SyncStoreError::CorruptRow("key_epoch"));
    }
    Ok(epoch)
}

fn sequence_to_sql(value: u64) -> Result<i64, SyncStoreError> {
    value.try_into().map_err(|_| SyncStoreError::SequenceExhausted)
}

fn now_ms() -> Result<i64, SyncStoreError> {
    let millis = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_err(|_| SyncStoreError::CorruptRow("system time"))?
        .as_millis();
    i64::try_from(millis).map_err(|_| SyncStoreError::SequenceExhausted)
}
