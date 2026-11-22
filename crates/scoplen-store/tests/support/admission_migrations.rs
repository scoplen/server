// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise closed endpoint ranges against the migration that published them.

macro_rules! apply_admission_migration {
    ($pool:expr, $directory:literal, $version:expr, $new:expr, $invalid:expr) => {{
        let mut migration = sqlx::migrate!($directory);
        migration.migrations.to_mut().retain(|step| step.version <= $version);
        migration.run($pool).await.expect("apply through the specified admission migration");
        let applied: i64 = sqlx::query_scalar("SELECT MAX(version) FROM _sqlx_migrations WHERE success")
            .fetch_one($pool).await.expect("applied migration version");
        assert_eq!(applied, $version);

        let insert = "INSERT INTO account_entry_admission \
            (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_admitted_ms,retire_at_ms) \
            VALUES ($1,1,$2,1000,1,0,1001,601001)";
        for endpoint in $new {
            sqlx::query(insert).bind(endpoint).bind([127_u8,0,0,1].as_slice())
                .execute($pool).await.expect("published endpoint accepts independent debt");
        }
        for endpoint in $invalid {
            let error = sqlx::query(insert).bind(endpoint).bind([127_u8,0,0,1].as_slice())
                .execute($pool).await.expect_err("endpoint lies outside the published range");
            assert!(
                error.as_database_error().is_some_and(|e| e.is_check_violation()),
                "migration {} must reject endpoint {endpoint} with a check constraint", $version
            );
        }
    }};
}

macro_rules! assert_retained_admission {
    ($pool:expr, $endpoints:expr) => {{
        for endpoint in $endpoints {
            let debt: (i64,i64,i64,Option<i64>,Option<i64>,i64,i64) = sqlx::query_as(
                "SELECT window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,last_admitted_ms,retire_at_ms \
                 FROM account_entry_admission WHERE endpoint=$1 AND kind=1 AND bucket_key=$2",
            )
            .bind(endpoint).bind([127_u8,0,0,1].as_slice()).fetch_one($pool)
            .await.expect("pre-upgrade admission bucket survives reopening");
            assert_eq!(debt, (1000,1,0,None,None,1001,601001), "endpoint {endpoint}");
        }
    }};
}

pub(super) use {apply_admission_migration, assert_retained_admission};
