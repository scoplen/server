// SPDX-License-Identifier: AGPL-3.0-only
//! Installed revision, candidate and receipt constraints after a populated upgrade.

use uuid::Uuid;

macro_rules! cases {
    ($module:ident, $pool:ty) => {
        pub(super) mod $module {
            use super::*;

            async fn rejects(pool: &$pool, table: &str, invalid_update: &str) {
                let error = sqlx::query(&format!("UPDATE {table} SET {invalid_update}"))
                    .execute(pool)
                    .await
                    .expect_err("invalid stored state");
                assert!(
                    error.as_database_error().is_some_and(|error| error.is_check_violation()),
                    "expected a check constraint for {table}: {invalid_update}"
                );
            }

            async fn installed(pool: &$pool, org: Uuid, foreign: &[u8]) {
                let insert = "INSERT INTO organization_auth_connections
                            (organization_id,revision,status,issuer,client_id,space_id,provider,trust_fingerprint,credential,created_at_ms)
                            VALUES ($1,$2,'active','https://issuer.example','Client','spc_A-1_','{}',$3,$4,1)";
                let revision = Uuid::now_v7();
                let execute = |organization: Vec<u8>| {
                    sqlx::query(insert)
                        .bind(organization)
                        .bind(revision.as_bytes().as_slice())
                        .bind([1_u8; 32].as_slice())
                        .bind([2_u8; 80].as_slice())
                        .execute(pool)
                };
                execute(org.as_bytes().to_vec()).await.expect("active revision");
                assert!(
                    execute(foreign.to_vec())
                        .await
                        .unwrap_err()
                        .as_database_error()
                        .unwrap()
                        .is_unique_violation()
                );
                for bad in [
                    "status='suspended'",
                    "credential=NULL",
                    "trust_fingerprint=NULL",
                    "provider=NULL",
                    "credential=trust_fingerprint",
                    "space_id='spc_'",
                    "space_id='SPC_team'",
                    "space_id='spc_a/b'",
                ] {
                    rejects(pool, "organization_auth_connections", bad).await;
                }
                sqlx::query("UPDATE organization_auth_connections SET revision=$1,status='suspended',credential=NULL,provider=NULL,trust_fingerprint=NULL")
                            .bind(Uuid::now_v7().as_bytes().as_slice()).execute(pool).await.expect("suspended public metadata only");
                rejects(pool, "organization_auth_connections", "status='active'").await;
                rejects(pool, "organization_auth_connections", "provider='{}'").await;
            }

            async fn check_activation_phases(pool: &$pool) {
                let table = "organization_auth_connection_activations";
                for bad in [
                    "expires_at_ms=1",
                    "expires_at_ms=300002",
                    "phase='claimed'",
                    "phase='verified'",
                    "phase='failed'",
                    "verifier=NULL",
                    "credential=NULL",
                    "state_digest=verifier",
                    "space_id='spc_/'",
                ] {
                    rejects(pool, table, bad).await;
                }
                for phase in ["claimed", "verified"] {
                    sqlx::query("UPDATE organization_auth_connection_activations SET phase=$1,verifier=NULL,expires_at_ms=300001")
                                .bind(phase).execute(pool).await.unwrap();
                    rejects(pool, table, "credential=NULL").await;
                    rejects(pool, table, "verifier=credential").await;
                }
                sqlx::query(
                    "UPDATE organization_auth_connection_activations SET phase='failed',credential=NULL",
                )
                .execute(pool)
                .await
                .unwrap();
            }

            async fn activation(pool: &$pool, org: Uuid, foreign: &[u8], account: &[u8]) {
                let generation = Uuid::now_v7();
                let other_generation = Uuid::now_v7();
                for (owner, draft) in [(org.as_bytes().as_slice(), generation), (foreign, other_generation)]
                {
                    sqlx::query(
                        "INSERT INTO organization_auth_drafts VALUES ($1,$2,'https://issuer.example',1)",
                    )
                    .bind(owner)
                    .bind(draft.as_bytes().as_slice())
                    .execute(pool)
                    .await
                    .unwrap();
                }
                let first = Uuid::now_v7();
                let second = Uuid::now_v7();
                for family in [first, second] {
                    sqlx::query("INSERT INTO account_browser_families
                                (family_id,account_id,credential_generation,dpop_jkt,trusted_origin,scope,created_at_ms,expires_at_ms)
                                VALUES ($1,$2,$3,$4,'https://browser.example','auth-connection:manage',1,2592000001)")
                                .bind(family.as_bytes().as_slice()).bind(account).bind(1_u64.to_be_bytes().as_slice())
                                .bind("A".repeat(43)).execute(pool).await.unwrap();
                }
                let add = |family: Uuid, draft: Uuid, state: u8| {
                    sqlx::query("INSERT INTO organization_auth_connection_activations
                                (id,organization_id,draft_generation,family_id,state_digest,browser_digest,nonce_digest,trust_fingerprint,
                                 issuer,client_id,space_id,provider,phase,credential,verifier,created_at_ms,expires_at_ms)
                                 VALUES ($1,$2,$3,$4,$5,$5,$5,$5,'https://issuer.example','Client','spc_X','{}','pending',$6,$6,1,2)")
                                .bind(Uuid::now_v7().into_bytes().to_vec()).bind(org.as_bytes().as_slice())
                                .bind(draft.into_bytes().to_vec()).bind(family.into_bytes().to_vec())
                                .bind(vec![state;32]).bind([2_u8;80].as_slice()).execute(pool)
                };
                assert!(
                    add(first, other_generation, 0)
                        .await
                        .unwrap_err()
                        .as_database_error()
                        .unwrap()
                        .is_foreign_key_violation()
                );
                add(first, generation, 1).await.expect("empty head and positive bounded expiry");
                // A replaced head remains a valid comparison value, never a cascading foreign key.
                sqlx::query("UPDATE organization_auth_connection_activations SET expected_revision=$1")
                    .bind(Uuid::now_v7().as_bytes().as_slice())
                    .execute(pool)
                    .await
                    .unwrap();
                check_activation_phases(pool).await;
                assert!(
                    add(first, generation, 2)
                        .await
                        .unwrap_err()
                        .as_database_error()
                        .unwrap()
                        .is_unique_violation()
                );
                assert!(
                    add(second, generation, 1)
                        .await
                        .unwrap_err()
                        .as_database_error()
                        .unwrap()
                        .is_unique_violation()
                );
                add(second, generation, 2).await.unwrap();
                sqlx::query("DELETE FROM account_browser_families WHERE family_id=$1")
                    .bind(second.as_bytes().as_slice())
                    .execute(pool)
                    .await
                    .unwrap();
                let families: Vec<Vec<u8>> =
                    sqlx::query_scalar("SELECT family_id FROM organization_auth_connection_activations")
                        .fetch_all(pool)
                        .await
                        .unwrap();
                assert_eq!(families, [first.as_bytes().to_vec()]);
                sqlx::query("DELETE FROM organization_auth_drafts WHERE generation=$1")
                    .bind(generation.as_bytes().as_slice())
                    .execute(pool)
                    .await
                    .unwrap();
                let count: i64 =
                    sqlx::query_scalar("SELECT COUNT(*) FROM organization_auth_connection_activations")
                        .fetch_one(pool)
                        .await
                        .unwrap();
                assert_eq!(count, 0);
                let heads: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organization_auth_connections")
                    .fetch_one(pool)
                    .await
                    .unwrap();
                assert_eq!(heads, 1);
            }

            async fn receipts(pool: &$pool, account: &[u8]) {
                let insert =
                    "INSERT INTO organization_auth_connection_receipts VALUES ($1,$2,$3,$2,$4,1,86400001)";
                let key = Uuid::now_v7();
                let execute = |length: usize| {
                    sqlx::query(insert)
                        .bind(account)
                        .bind([1_u8; 32].as_slice())
                        .bind(key.as_bytes().as_slice())
                        .bind(vec![1_u8; length])
                        .execute(pool)
                };
                for length in [0, 8193] {
                    assert!(
                        execute(length)
                            .await
                            .unwrap_err()
                            .as_database_error()
                            .unwrap()
                            .is_check_violation()
                    );
                }
                execute(8192).await.unwrap();
                let table = "organization_auth_connection_receipts";
                for bad in [
                    "request_digest=NULL",
                    "response_json=NULL",
                    "created_at_ms=NULL",
                    "expires_at_ms=NULL",
                    "expires_at_ms=86400000",
                ] {
                    rejects(pool, table, bad).await;
                }
                sqlx::query("UPDATE organization_auth_connection_receipts SET request_digest=NULL,response_json=NULL,created_at_ms=NULL,expires_at_ms=NULL")
                            .execute(pool).await.expect("spent key tombstone");
                assert!(execute(1).await.unwrap_err().as_database_error().unwrap().is_unique_violation());
            }

            pub(in super::super) async fn check(pool: &$pool, org: Uuid, foreign_membership: Uuid) {
                let (foreign, account): (Vec<u8>, Vec<u8>) = sqlx::query_as(
                    "SELECT organization_id,account_id FROM organization_memberships WHERE id=$1",
                )
                .bind(foreign_membership.as_bytes().as_slice())
                .fetch_one(pool)
                .await
                .unwrap();
                installed(pool, org, &foreign).await;
                activation(pool, org, &foreign, &account).await;
                receipts(pool, &account).await;
            }
        }
    };
}

cases!(sqlite, sqlx::SqlitePool);
#[cfg(feature = "postgres-integration")]
cases!(postgres, sqlx::PgPool);
