// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_support as support;
use OperatorAdmissionDecision as Decision;
use OperatorAuthEndpoint as Endpoint;
use OperatorPrivateBucket as Private;

const NOW: i64 = 1_800_000_030_000;

fn source() -> IpAddr {
    "192.0.2.80".parse().expect("source")
}

macro_rules! quotas {
    ($first:expr,$second:expr) => {{
        let first = &$first;
        let second = &$second;
        let mut jobs = Vec::new();
        for index in 0..40 {
            let store = if index % 2 == 0 { first.clone() } else { second.clone() };
            jobs.push(tokio::spawn(async move {
                store
                    .admit_operator_auth_source_with_clock(Endpoint::SetupOptions, source(), || {
                        Ok(NOW)
                    })
                    .await
            }));
        }
        let mut admitted = 0;
        for job in jobs {
            match job.await.expect("join").expect("admission") {
                Decision::Admitted => admitted += 1,
                Decision::RateLimited(wait) => assert_eq!(wait, 30),
            }
        }
        assert_eq!(admitted, 30);
        assert!(matches!(
            second
                .admit_operator_auth_source_with_clock(
                    Endpoint::SetupOptions,
                    "::ffff:192.0.2.80".parse().expect("mapped source"),
                    || Ok(NOW)
                )
                .await,
            Ok(Decision::RateLimited(_))
        ));
        assert_eq!(
            second
                .admit_operator_auth_source_with_clock(Endpoint::SetupFinish, source(), || Ok(NOW))
                .await
                .expect("separate endpoint"),
            Decision::Admitted
        );
        let digest = [9; 32];
        for _ in 0..5 {
            assert_eq!(
                first
                    .admit_operator_auth_private_with_clock(
                        Endpoint::SetupOptions,
                        Private::SetupDigest(&digest),
                        || Ok(NOW)
                    )
                    .await
                    .expect("nonexistent digest admitted"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_private_with_clock(
                    Endpoint::SetupOptions,
                    Private::SetupDigest(&digest),
                    || Ok(NOW)
                )
                .await,
            Ok(Decision::RateLimited(_))
        ));
        assert_eq!(
            second
                .admit_operator_auth_private_with_clock(
                    Endpoint::SetupFinish,
                    Private::SetupDigest(&digest),
                    || Ok(NOW)
                )
                .await
                .expect("separate digest endpoint"),
            Decision::Admitted
        );
        let ceremony = uuid::Uuid::now_v7();
        for _ in 0..5 {
            assert_eq!(
                first
                    .admit_operator_auth_private_with_clock(
                        Endpoint::LoginFinish,
                        Private::Ceremony(ceremony),
                        || Ok(NOW)
                    )
                    .await
                    .expect("nonexistent ceremony admitted"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_private_with_clock(
                    Endpoint::LoginFinish,
                    Private::Ceremony(ceremony),
                    || Ok(NOW)
                )
                .await,
            Ok(Decision::RateLimited(_))
        ));
        let operator = uuid::Uuid::now_v7();
        for _ in 0..10 {
            assert_eq!(
                first
                    .admit_operator_auth_private_with_clock(
                        Endpoint::LoginFinish,
                        Private::AuthenticatedOperator(operator),
                        || Ok(NOW)
                    )
                    .await
                    .expect("verified operator admission"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_private_with_clock(
                    Endpoint::LoginFinish,
                    Private::AuthenticatedOperator(operator),
                    || Ok(NOW)
                )
                .await,
            Ok(Decision::RateLimited(_))
        ));
        assert_eq!(
            second
                .admit_operator_auth_private_with_clock(
                    Endpoint::Refresh,
                    Private::AuthenticatedOperator(operator),
                    || Ok(NOW)
                )
                .await
                .expect("separate refresh window"),
            Decision::Admitted
        );
        for _ in 0..10 {
            assert_eq!(
                first
                    .admit_operator_auth_private_with_clock(
                        Endpoint::Logout,
                        Private::AuthenticatedOperator(operator),
                        || Ok(NOW)
                    )
                    .await
                    .expect("independent logout quota"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_private_with_clock(
                    Endpoint::Logout,
                    Private::AuthenticatedOperator(operator),
                    || Ok(NOW)
                )
                .await,
            Ok(Decision::RateLimited(_))
        ));
        for _ in 0..30 {
            assert_eq!(
                first
                    .admit_operator_auth_source_with_clock(Endpoint::Logout, source(), || Ok(NOW))
                    .await
                    .expect("logout source quota"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_source_with_clock(Endpoint::Logout, source(), || Ok(NOW))
                .await,
            Ok(Decision::RateLimited(_))
        ));
        assert!(matches!(
            first
                .admit_operator_auth_private_with_clock(
                    Endpoint::LoginOptions,
                    Private::SetupDigest(&digest),
                    || Ok(NOW)
                )
                .await,
            Err(OperatorAdmissionError::InvalidInput)
        ));
        assert!(matches!(
            first
                .admit_operator_auth_private_with_clock(
                    Endpoint::SetupFinish,
                    Private::Ceremony(ceremony),
                    || Ok(NOW)
                )
                .await,
            Err(OperatorAdmissionError::InvalidInput)
        ));
        assert_eq!(
            second
                .admit_operator_auth_source_with_clock(Endpoint::SetupOptions, source(), || Ok(
                    NOW + 29_999
                ))
                .await
                .expect("last millisecond of exhausted window"),
            Decision::RateLimited(1)
        );
        let mut jobs = Vec::new();
        for index in 0..40 {
            let store = if index % 2 == 0 { first.clone() } else { second.clone() };
            jobs.push(tokio::spawn(async move {
                store
                    .admit_operator_auth_source_with_clock(Endpoint::SetupOptions, source(), || {
                        Ok(NOW + 30_000)
                    })
                    .await
            }));
        }
        let mut admitted = 0;
        for job in jobs {
            match job.await.expect("rollover join").expect("rollover admission") {
                Decision::Admitted => admitted += 1,
                Decision::RateLimited(wait) => assert_eq!(wait, 60),
            }
        }
        assert_eq!(admitted, 30, "a new fixed window has an independent quota");
        let device_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_auth_admission")
            .fetch_one(first.pool())
            .await
            .expect("device admission untouched");
        assert_eq!(device_rows, 0);
    }};
}

#[tokio::test]
async fn sqlite_durable_quotas_across_replicas() {
    let dir = std::env::temp_dir().join(format!("scoplen-operator-quotas-{}", Uuid::new_v4()));
    let store = SqliteStore::open(&dir.join("store.sqlite")).await.expect("SQLite");
    let replica = SqliteStore::open(&dir.join("store.sqlite")).await.expect("second pool");
    quotas!(store, replica);
    store.pool().close().await;
    replica.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_durable_quotas_across_replicas() {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PG fixture");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture admin pool");
    let schema = format!("operator_quotas_{}", Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("PG URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = PostgresStore::connect(url.as_str()).await.expect("PG store");
    let replica = PostgresStore::connect(url.as_str()).await.expect("second pool");
    quotas!(store, replica);
    store.pool().close().await;
    replica.pool().close().await;
    assert!(
        schema.starts_with("operator_quotas_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}
