// SPDX-License-Identifier: AGPL-3.0-only
//! Digest-only admission capabilities; only a complete authorized transaction can consume one.

use scoplen_crypto::account_capability_digest;
use sqlx::{Postgres, Row, Sqlite, Transaction};
use uuid::Uuid;

use crate::account_entry_admission::{
    AccountEntryStateError, postgres_account_entry_now, sqlite_account_entry_now, valid_id,
};

pub(crate) const CAPABILITY_CAPACITY: i64 = 4_096;
pub(crate) const ACCOUNT_CAPABILITY_CAPACITY: i64 = 4;

/// A provisional consumption, which grants no Device or session authority by itself.
/// Roll back the owning transaction on any later rate rejection or failed proof.
pub struct ClaimedAccountAdmissionCapability {
    account_id: Uuid,
    credential_generation: u64,
    snapshot_digest: [u8; 32],
    expires_at_ms: i64,
}

impl ClaimedAccountAdmissionCapability {
    pub(crate) fn expires_at_ms(&self) -> i64 {
        self.expires_at_ms
    }

    #[must_use]
    pub fn account_id(&self) -> Uuid {
        self.account_id
    }

    #[must_use]
    pub fn credential_generation(&self) -> u64 {
        self.credential_generation
    }

    #[must_use]
    pub fn snapshot_digest(&self) -> &[u8; 32] {
        &self.snapshot_digest
    }
}

impl std::fmt::Debug for ClaimedAccountAdmissionCapability {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str("ClaimedAccountAdmissionCapability([REDACTED])")
    }
}

macro_rules! capabilities {
    ($db:ty,$claim:ident,$finish:ident,$now:ident,$length:literal) => {
        /// Provisionally consume an unexpired digest in the owning admission transaction.
        ///
        /// Acquire the Account-entry singleton before Account/business/audit locks. SQLite
        /// requires BEGIN IMMEDIATE. This checks no possession proof or current snapshot: the
        /// coordinator must verify all bindings and append mandatory audit in this same tx.
        /// Removal represents spent state, freeing capacity only on confirmed commit.
        /// # Errors
        /// Corrupt state or storage errors require rollback of the whole transaction.
        pub async fn $claim(
            tx: &mut Transaction<'_, $db>,
            token: &[u8; 32],
        ) -> Result<Option<ClaimedAccountAdmissionCapability>, AccountEntryStateError> {
            let now = $now(tx).await?;
            let digest = account_capability_digest(token);
            let length=$length;
            let row = sqlx::query(&format!("SELECT CASE WHEN {length}(account_id)=16 THEN account_id END AS account_id,credential_generation,CASE WHEN {length}(snapshot_digest)=32 THEN snapshot_digest END AS snapshot_digest,issued_at_ms,expires_at_ms FROM account_admission_capabilities WHERE token_digest=$1"))
                .bind(digest.as_slice()).fetch_optional(&mut **tx).await?;
            let Some(row) = row else { return Ok(None); };
            let account:Vec<u8> = row.try_get("account_id").map_err(|_|AccountEntryStateError::Integrity)?;
            let snapshot:Vec<u8> = row.try_get("snapshot_digest").map_err(|_|AccountEntryStateError::Integrity)?;
            let generation:i64 = row.try_get("credential_generation")?;
            let issued:i64 = row.try_get("issued_at_ms")?;
            let expires:i64 = row.try_get("expires_at_ms")?;
            let account_id = Uuid::from_slice(&account).map_err(|_|AccountEntryStateError::Integrity)?;
            valid_id(account_id).map_err(|_|AccountEntryStateError::Integrity)?;
            if issued<=0 || now<issued || issued.checked_add(300_000)!=Some(expires) || generation<=0 {
                return Err(AccountEntryStateError::Integrity);
            }
            let snapshot_digest=snapshot.try_into().map_err(|_|AccountEntryStateError::Integrity)?;
            if now>=expires { return Ok(None); }
            if sqlx::query("DELETE FROM account_admission_capabilities WHERE token_digest=$1")
                .bind(digest.as_slice()).execute(&mut **tx).await?.rows_affected()!=1 {
                return Err(AccountEntryStateError::Integrity);
            }
            Ok(Some(ClaimedAccountAdmissionCapability {
                account_id,credential_generation:u64::try_from(generation).map_err(|_|AccountEntryStateError::Integrity)?,
                snapshot_digest,expires_at_ms:expires,
            }))
        }

        /// Recheck trusted expiry after all admission proof, business and audit work.
        /// Commit immediately after this call; an error requires complete rollback.
        /// # Errors
        /// Fails on expired capability, corrupt clock or unavailable storage.
        pub async fn $finish(
            tx:&mut Transaction<'_,$db>,
            claim:ClaimedAccountAdmissionCapability,
        ) -> Result<(),AccountEntryStateError> {
            if $now(tx).await?>=claim.expires_at_ms {
                return Err(AccountEntryStateError::ChallengeExpired);
            }
            Ok(())
        }
    };
}

capabilities!(
    Sqlite,
    claim_sqlite_account_admission_capability_in_transaction,
    finish_sqlite_account_admission_capability_in_transaction,
    sqlite_account_entry_now,
    "length"
);
capabilities!(
    Postgres,
    claim_postgres_account_admission_capability_in_transaction,
    finish_postgres_account_admission_capability_in_transaction,
    postgres_account_entry_now,
    "octet_length"
);
