// SPDX-License-Identifier: AGPL-3.0-only
//! Storage fixtures for native withdrawal through the public team API.

use super::{AuthBackend, Fixture, Uuid};
use scoplen_store::RelationalStore as _;

macro_rules! on_store {
    ($fixture:expr, $pool:ident, $body:block) => {
        match &$fixture.backend {
            AuthBackend::Sqlite(store) => {
                let $pool = store.pool();
                $body
            }
            AuthBackend::Postgres(store) => {
                let $pool = store.pool();
                $body
            }
        }
    };
}

pub(super) struct ScopedVault(Uuid);

impl ScopedVault {
    // The native team request performs all membership transitions. The stored
    // wraps are opaque fixtures while the production sharing surface is gated.
    pub(super) async fn seed(
        fixture: &Fixture,
        organization: Uuid,
        recipients: &[(Uuid, Uuid, &str)],
    ) -> Self {
        let vault = Uuid::now_v7();
        on_store!(fixture, pool, {
            sqlx::query("INSERT INTO sync_vaults(vault_id,kind) VALUES ($1,'shared')")
                .bind(vault.as_bytes().as_slice())
                .execute(pool)
                .await
                .expect("Shared vault fixture");
            sqlx::query(
                "INSERT INTO organization_shared_vaults(vault_id,organization_id) VALUES ($1,$2)",
            )
            .bind(vault.as_bytes().as_slice())
            .bind(organization.as_bytes().as_slice())
            .execute(pool)
            .await
            .expect("Organization ownership fixture");
            for (account, membership, role) in recipients {
                let wrap = &[42_u8][..];
                sqlx::query("INSERT INTO sync_vault_members(vault_id,account_id,role,key_epoch,wrapped_vault_key) VALUES ($1,$2,$3,1,$4)")
                    .bind(vault.as_bytes().as_slice())
                    .bind(account.as_bytes().as_slice())
                    .bind(*role)
                    .bind(wrap)
                    .execute(pool)
                    .await
                    .expect("Shared recipient fixture");
                sqlx::query("INSERT INTO organization_shared_vault_recipients(vault_id,organization_id,membership_id,account_id) VALUES ($1,$2,$3,$4)")
                    .bind(vault.as_bytes().as_slice())
                    .bind(organization.as_bytes().as_slice())
                    .bind(membership.as_bytes().as_slice())
                    .bind(account.as_bytes().as_slice())
                    .execute(pool)
                    .await
                    .expect("exact Membership fixture");
                sqlx::query("INSERT INTO sync_vault_member_keys(vault_id,account_id,epoch,wrapped_vault_key) VALUES ($1,$2,1,$3)")
                    .bind(vault.as_bytes().as_slice())
                    .bind(account.as_bytes().as_slice())
                    .bind(wrap)
                    .execute(pool)
                    .await
                    .expect("served epoch fixture");
            }
        });
        Self(vault)
    }

    pub(super) async fn reject_foreign_membership(
        &self,
        fixture: &Fixture,
        account: Uuid,
        foreign: Uuid,
    ) {
        let rejected = on_store!(fixture, pool, {
            sqlx::query(
                "UPDATE organization_shared_vault_recipients SET membership_id=$1
                 WHERE vault_id=$2 AND account_id=$3",
            )
            .bind(foreign.as_bytes().as_slice())
            .bind(self.0.as_bytes().as_slice())
            .bind(account.as_bytes().as_slice())
            .execute(pool)
            .await
            .map(|_| ())
        });
        assert!(
            rejected
                .expect_err("another Organization's Membership must be refused")
                .as_database_error()
                .is_some_and(sqlx::error::DatabaseError::is_foreign_key_violation)
        );
    }

    pub(super) async fn assert_state(
        &self,
        fixture: &Fixture,
        rotation_pending: bool,
        remaining: Option<Uuid>,
    ) {
        let account = remaining.as_ref().map(|id| id.as_bytes().as_slice());
        let recipients = i64::from(remaining.is_some());
        let state = on_store!(fixture, pool, {
            sqlx::query_as::<_, (bool, i64, i64, i64, i64)>(
                "SELECT v.rotation_pending,
                    (SELECT COUNT(*) FROM organization_shared_vault_recipients WHERE vault_id=v.vault_id),
                    (SELECT COUNT(*) FROM sync_vault_members WHERE vault_id=v.vault_id),
                    (SELECT COUNT(*) FROM sync_vault_member_keys WHERE vault_id=v.vault_id),
                    (SELECT COUNT(*) FROM sync_vault_member_keys WHERE vault_id=v.vault_id AND account_id=$2)
                 FROM sync_vaults v WHERE v.vault_id=$1",
            )
            .bind(self.0.as_bytes().as_slice())
            .bind(account)
            .fetch_one(pool)
            .await
            .expect("stored Shared vault state")
        });
        assert_eq!(state, (rotation_pending, recipients, recipients, recipients, recipients));
    }
}
