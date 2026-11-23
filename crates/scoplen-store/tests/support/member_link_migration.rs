// SPDX-License-Identifier: AGPL-3.0-only
//! D-170 storage constraints and the populated native Membership upgrade.

use uuid::Uuid;

macro_rules! cases {
    ($module:ident, $pool:ty) => {
        pub(super) mod $module {
            use super::*;

            enum Violation {
                Check,
                ForeignKey,
                Unique,
            }

            fn assert_violation(error: sqlx::Error, violation: Violation) {
                let database = error.as_database_error().expect("database constraint");
                assert!(
                    match violation {
                        Violation::Check => database.is_check_violation(),
                        Violation::ForeignKey => database.is_foreign_key_violation(),
                        Violation::Unique => database.is_unique_violation(),
                    },
                    "unexpected constraint error: {error}"
                );
            }

            async fn member(pool: &$pool, organization: Uuid) -> (Uuid, Uuid, Uuid) {
                let account = Uuid::now_v7();
                let membership = Uuid::now_v7();
                let family = Uuid::now_v7();
                sqlx::query("INSERT INTO identity_accounts
                             (account_id,account_signing_public_key,account_kem_public_key,created_at_ms)
                             VALUES ($1,$2,$2,1)")
                    .bind(account.as_bytes().as_slice())
                    .bind([8_u8; 32].as_slice()).execute(pool).await.unwrap();
                sqlx::query("INSERT INTO organization_memberships
                             (id,organization_id,account_id,status,roles_json,created_at_ms,updated_at_ms)
                             VALUES ($1,$2,$3,'active','[\"member\"]',1,1)")
                    .bind(membership.as_bytes().as_slice())
                    .bind(organization.as_bytes().as_slice())
                    .bind(account.as_bytes().as_slice()).execute(pool).await.unwrap();
                sqlx::query("INSERT INTO account_browser_families
                             (family_id,account_id,credential_generation,dpop_jkt,trusted_origin,scope,created_at_ms,expires_at_ms)
                             VALUES ($1,$2,$3,$4,'https://browser.example','auth-links:self',1,2592000001)")
                    .bind(family.as_bytes().as_slice()).bind(account.as_bytes().as_slice())
                    .bind(1_u64.to_be_bytes().as_slice()).bind("A".repeat(43))
                    .execute(pool).await.unwrap();
                (account, membership, family)
            }

            async fn check_link_rows(pool: &$pool, organization: Uuid, membership: Uuid, other: Uuid, foreign: Uuid) {
                let insert = |org: Uuid, member: Uuid, comparison: Vec<u8>| sqlx::query(
                    "INSERT INTO organization_auth_links
                     (id,organization_id,membership_id,subject_comparison,created_at_ms)
                     VALUES ($1,$2,$3,$4,1)"
                )
                    .bind(Uuid::now_v7().into_bytes().to_vec())
                    .bind(org.into_bytes().to_vec()).bind(member.into_bytes().to_vec())
                    .bind(comparison).execute(pool);
                let initial: (i64, String, i64) = sqlx::query_as(
                    "SELECT auth_link_generation, roles_json, updated_at_ms FROM organization_memberships WHERE id=$1",
                )
                    .bind(membership.as_bytes().as_slice()).fetch_one(pool).await.unwrap();
                assert_eq!(initial, (0, "[\"owner\"]".into(), 456));
                assert_violation(
                    sqlx::query("UPDATE organization_memberships SET auth_link_generation=-1 WHERE id=$1")
                        .bind(membership.as_bytes().as_slice()).execute(pool).await.unwrap_err(),
                    Violation::Check,
                );
                assert_violation(insert(organization, foreign, vec![1; 32]).await.unwrap_err(), Violation::ForeignKey);
                assert_violation(insert(organization, membership, vec![1; 31]).await.unwrap_err(), Violation::Check);
                insert(organization, membership, vec![1; 32]).await.unwrap();
                assert_violation(insert(organization, membership, vec![2; 32]).await.unwrap_err(), Violation::Unique);
                assert_violation(insert(organization, other, vec![1; 32]).await.unwrap_err(), Violation::Unique);
                insert(organization, other, vec![2; 32]).await.unwrap();
                let foreign_org: Vec<u8> = sqlx::query_scalar("SELECT organization_id FROM organization_memberships WHERE id=$1")
                    .bind(foreign.as_bytes().as_slice()).fetch_one(pool).await.unwrap();
                let foreign_org = Uuid::from_slice(&foreign_org).unwrap();
                insert(foreign_org, foreign, vec![1; 32]).await.unwrap();
            }

            async fn check_attempt_rows(
                pool: &$pool, organization: Uuid, account: Uuid, membership: Uuid,
                family: Uuid, foreign_member: Uuid, foreign_family: Uuid,
            ) {
                let attempt = Uuid::now_v7();
                let revision = Uuid::now_v7();
                let insert = |member: Uuid, owner: Uuid, id: Uuid, state: u8| sqlx::query(
                    "INSERT INTO organization_auth_link_attempts
                     (id,organization_id,membership_id,account_id,family_id,connection_revision,
                      link_generation,state_digest,browser_digest,nonce_digest,phase,verifier,created_at_ms,expires_at_ms)
                     VALUES ($1,$2,$3,$4,$5,$6,0,$7,$8,$9,'pending',$10,1,300001)"
                )
                    .bind(id.into_bytes().to_vec()).bind(organization.into_bytes().to_vec())
                    .bind(member.into_bytes().to_vec()).bind(account.into_bytes().to_vec())
                    .bind(owner.into_bytes().to_vec()).bind(revision.into_bytes().to_vec())
                    .bind(vec![state; 32]).bind(vec![2_u8; 32]).bind(vec![3_u8; 32])
                    .bind(vec![4_u8; 80]).execute(pool);
                assert_violation(insert(foreign_member, family, attempt, 1).await.unwrap_err(), Violation::ForeignKey);
                assert_violation(insert(membership, foreign_family, attempt, 1).await.unwrap_err(), Violation::ForeignKey);
                insert(membership, family, attempt, 1).await.unwrap();
                assert_violation(insert(membership, family, Uuid::now_v7(), 2).await.unwrap_err(), Violation::Unique);
                let update = |fields: &str| {
                    let query = format!("UPDATE organization_auth_link_attempts SET {fields} WHERE id=$1");
                    async move {
                        sqlx::query(&query).bind(attempt.as_bytes().as_slice()).execute(pool).await
                    }
                };
                for invalid in [
                    "phase='claimed'",
                    "phase='verified',verifier=NULL",
                    "phase='failed'",
                    "subject_comparison=state_digest",
                    "link_generation=-1",
                    "connection_revision=state_digest",
                    "expires_at_ms=300002",
                ] {
                    assert_violation(update(invalid).await.unwrap_err(), Violation::Check);
                }
                update("phase='claimed',verifier=NULL").await.unwrap();
                sqlx::query("UPDATE organization_auth_link_attempts SET phase='verified',subject_comparison=$1 WHERE id=$2")
                    .bind([9_u8; 32].as_slice()).bind(attempt.as_bytes().as_slice())
                    .execute(pool).await.unwrap();
                sqlx::query("DELETE FROM account_browser_families WHERE family_id=$1")
                    .bind(family.as_bytes().as_slice()).execute(pool).await.unwrap();
                let attempts: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_auth_link_attempts")
                    .fetch_one(pool).await.unwrap();
                assert_eq!(attempts, 0);
                let links: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_auth_links")
                    .fetch_one(pool).await.unwrap();
                assert_eq!(links, 3);
            }

            pub(in super::super) async fn check(
                pool: &$pool, organization: Uuid, original: Uuid, foreign_member: Uuid, foreign_family: Uuid,
            ) {
                let (account, membership, family) = member(pool, organization).await;
                check_link_rows(pool, organization, original, membership, foreign_member).await;
                check_attempt_rows(pool, organization, account, membership, family, foreign_member, foreign_family).await;
            }
        }
    };
}

cases!(sqlite, sqlx::SqlitePool);
#[cfg(feature = "postgres-integration")]
cases!(postgres, sqlx::PgPool);
