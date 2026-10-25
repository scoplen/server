// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{RelationalStore, SqliteStore};

const NEW_MIGRATION: i64 = 20_261_025_010_000;

#[derive(Debug, Eq, PartialEq, sqlx::FromRow)]
struct SavedBucket {
    endpoint: i64,
    kind: i64,
    bucket_key: Vec<u8>,
    window_start_ms: i64,
    attempts: i64,
    failure_streak: i64,
    last_failure_ms: Option<i64>,
    cooldown_until_ms: Option<i64>,
    retain_until_ms: i64,
}

const SNAPSHOT: &str = "SELECT endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,retain_until_ms FROM operator_auth_admission ORDER BY endpoint,kind,bucket_key";

macro_rules! populate {
    ($pool:expr) => {{
        let now = time::OffsetDateTime::now_utc().unix_timestamp() * 1000;
        for (endpoint, kind, key) in [
            (1_i64, 1_i64, vec![192, 0, 2, 99]),
            (2, 1, vec![192, 0, 2, 99]),
            (3, 1, vec![192, 0, 2, 99]),
            (4, 1, vec![192, 0, 2, 99]),
            (5, 1, vec![192, 0, 2, 99]),
            (1, 2, vec![11; 32]),
            (2, 2, vec![11; 32]),
            (4, 3, uuid::Uuid::now_v7().as_bytes().to_vec()),
            (4, 4, uuid::Uuid::now_v7().as_bytes().to_vec()),
            (5, 4, uuid::Uuid::now_v7().as_bytes().to_vec()),
        ] {
            sqlx::query("INSERT INTO operator_auth_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,last_failure_ms,cooldown_until_ms,retain_until_ms) VALUES ($1,$2,$3,$4,30,3,$4,$5,$6)")
                .bind(endpoint).bind(kind).bind(key).bind(now).bind(now + 60_000).bind(now + 600_000)
                .execute($pool).await.expect("populated historical debt");
        }
        sqlx::query("INSERT INTO operator_dpop_replays (dpop_jkt,jti_digest,retain_until_ms) VALUES ($1,$2,$3)")
            .bind("A".repeat(43)).bind([91_u8; 32].as_slice()).bind(now + 600_000)
            .execute($pool).await.expect("historical proof retention");
        sqlx::query_as::<_, SavedBucket>(SNAPSHOT).fetch_all($pool).await.expect("before snapshot")
    }};
}

macro_rules! upgraded {
    ($store:expr, $before:expr, $indexes:expr) => {{
        use scoplen_store::operator_admission::{OperatorAdmissionDecision, OperatorAuthEndpoint, OperatorPrivateBucket};
        let store = &$store;
        let after = sqlx::query_as::<_, SavedBucket>(SNAPSHOT).fetch_all(store.pool()).await.expect("after snapshot");
        assert_eq!($before, after, "every historical identity, count, streak and timestamp survives");
        let replay: Vec<u8> = sqlx::query_scalar("SELECT jti_digest FROM operator_dpop_replays")
            .fetch_one(store.pool()).await.expect("replay retained");
        assert_eq!(replay, [91; 32]);
        let indexes: i64 = sqlx::query_scalar($indexes).fetch_one(store.pool()).await.expect("retained index");
        assert_eq!(indexes, 1);
        let source = "192.0.2.99".parse().expect("source");
        for endpoint in [OperatorAuthEndpoint::SetupOptions, OperatorAuthEndpoint::SetupFinish,
            OperatorAuthEndpoint::LoginOptions, OperatorAuthEndpoint::LoginFinish, OperatorAuthEndpoint::Refresh] {
            assert!(matches!(store.admit_operator_auth_source(endpoint, source).await,
                Ok(OperatorAdmissionDecision::RateLimited(_))), "old debt remains enforced");
        }
        assert_eq!(store.admit_operator_auth_source(OperatorAuthEndpoint::Logout, source).await.expect("new independent source"), OperatorAdmissionDecision::Admitted);
        assert_eq!(store.admit_operator_auth_private(OperatorAuthEndpoint::Logout,
            OperatorPrivateBucket::AuthenticatedOperator(uuid::Uuid::now_v7())).await.expect("new independent private"), OperatorAdmissionDecision::Admitted);
        for (endpoint, kind, key) in [(7_i64, 1_i64, vec![1; 4]), (6, 2, vec![1; 32]),
            (6, 3, vec![1; 16]), (6, 4, vec![1; 15]), (6, 1, vec![1; 3])] {
            assert!(sqlx::query("INSERT INTO operator_auth_admission (endpoint,kind,bucket_key,window_start_ms,attempts,failure_streak,retain_until_ms) VALUES ($1,$2,$3,1,0,0,1)")
                .bind(endpoint).bind(kind).bind(key).execute(store.pool()).await.is_err(), "logical constraints remain equivalent");
        }
        assert!(sqlx::query("INSERT INTO operator_auth_admission SELECT * FROM operator_auth_admission WHERE endpoint=1 AND kind=1")
            .execute(store.pool()).await.is_err(), "primary key remains enforced");
    }};
}

#[tokio::test]
async fn sqlite_logout_forward_migration_preserves_populated_debt_and_constraints() {
    use sqlx::sqlite::{SqliteConnectOptions, SqlitePoolOptions};
    let directory =
        std::env::temp_dir().join(format!("scoplen-logout-migration-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("owned directory");
    let path = directory.join("store.sqlite");
    let pool = SqlitePoolOptions::new()
        .max_connections(1)
        .connect_with(
            SqliteConnectOptions::new().filename(&path).create_if_missing(true).foreign_keys(true),
        )
        .await
        .expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/sqlite");
    old.migrations.to_mut().retain(|migration| migration.version < NEW_MIGRATION);
    old.run(&pool).await.expect("historical migrations");
    let before = populate!(&pool);
    pool.close().await;
    let store = SqliteStore::open(&path).await.expect("forward upgrade");
    upgraded!(
        store,
        before,
        "SELECT COUNT(*) FROM sqlite_schema WHERE type='index' AND name='operator_auth_admission_by_retention'"
    );
    store.pool().close().await;
    let reopened = SqliteStore::open(&path).await.expect("idempotent reopen");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_auth_admission")
        .fetch_one(reopened.pool())
        .await
        .expect("persisted buckets");
    assert_eq!(rows, 12);
    reopened.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_logout_forward_migration_preserves_populated_debt_and_constraints() {
    let database =
        std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("disposable PostgreSQL fixture");
    let admin = sqlx::PgPool::connect(&database).await.expect("admin pool");
    let schema = format!("logout_migration_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&admin).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let pool = sqlx::PgPool::connect(url.as_str()).await.expect("historical pool");
    let mut old = sqlx::migrate!("./migrations/postgres");
    old.migrations.to_mut().retain(|migration| migration.version < NEW_MIGRATION);
    old.run(&pool).await.expect("historical migrations");
    let before = populate!(&pool);
    pool.close().await;
    let store = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("forward upgrade");
    upgraded!(
        store,
        before,
        "SELECT COUNT(*) FROM pg_indexes WHERE schemaname=current_schema() AND indexname='operator_auth_admission_by_retention'"
    );
    store.pool().close().await;
    let reopened =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("idempotent reopen");
    let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_auth_admission")
        .fetch_one(reopened.pool())
        .await
        .expect("persisted buckets");
    assert_eq!(rows, 12);
    reopened.pool().close().await;
    assert!(
        schema.starts_with("logout_migration_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&admin)
        .await
        .expect("remove owned schema");
    admin.close().await;
}
