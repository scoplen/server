// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
mod support;

#[cfg(feature = "postgres-integration")]
use scoplen_store::PostgresStore;
use scoplen_store::{
    RelationalStore, SqliteStore,
    refresh_retention::{RefreshCleanupError, RefreshCleanupReport},
};
use std::time::{SystemTime, UNIX_EPOCH};
use uuid::Uuid;

const FAMILY_MS: i64 = 2_592_000_000;

fn now_ms() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
        .expect("timestamp")
}

macro_rules! backend {
    ($module:ident, $db:ty, $active:expr) => {
        mod $module {
            use super::*;

            pub async fn seed(pool: &sqlx::Pool<$db>) -> Uuid {
                let id = Uuid::now_v7();
                sqlx::query("INSERT INTO identity_accounts (account_id,account_signing_public_key,account_kem_public_key,created_at_ms) VALUES ($1,$2,$2,1)")
                    .bind(id.as_bytes().as_slice()).bind([1_u8;32].as_slice())
                    .execute(pool).await.expect("account");
                sqlx::query("INSERT INTO identity_devices (device_id,account_id,certificate,active,created_at_ms) VALUES ($1,$1,$2,$3,1)")
                    .bind(id.as_bytes().as_slice()).bind([1_u8].as_slice()).bind($active)
                    .execute(pool).await.expect("device");
                sqlx::query("INSERT INTO deployment_operators (operator_id,active,created_at_s) VALUES ($1,1,1)")
                    .bind(id.as_bytes().as_slice()).execute(pool).await.expect("operator");
                sqlx::query("INSERT INTO operator_credentials (credential_id,operator_id,user_handle,trusted_origin,rp_id,credential_version,credential_state,active,created_at_s) VALUES ($1,$1,$1,'https://refresh.example.test','refresh.example.test',1,$2,1,1)")
                    .bind(id.as_bytes().as_slice()).bind([1_u8].as_slice())
                    .execute(pool).await.expect("credential");
                id
            }

            pub async fn family(
                pool: &sqlx::Pool<$db>,
                principal: Uuid,
                kind: &str,
                expires: i64,
                count: u16,
                revoked: bool,
            ) -> Uuid {
                let id = Uuid::now_v7();
                let created = expires - FAMILY_MS;
                let columns = if kind == "device" {
                    "family_id,account_id,device_id,dpop_jkt,audience,scope,created_at_ms,expires_at_ms,revoked_at_ms"
                } else {
                    "family_id,operator_id,credential_id,dpop_jkt,audience,scope,created_at_ms,expires_at_ms,revoked_at_ms,principal_kind,trusted_origin"
                };
                let tail = if kind == "device" { "" } else { ",'operator','https://refresh.example.test'" };
                sqlx::query(&format!("INSERT INTO {kind}_refresh_families ({columns}) VALUES ($1,$2,$2,$3,$4,'test',$5,$6,$7{tail})"))
                    .bind(id.as_bytes().as_slice()).bind(principal.as_bytes().as_slice())
                    .bind("a".repeat(43)).bind(if kind=="device" {"spl-api/1"}else{"spl-admin/1"})
                    .bind(created).bind(expires).bind(revoked.then_some(created))
                    .execute(pool).await.expect("refresh family");
                for n in 0..count {
                    let mut digest = [0_u8;32];
                    digest[..16].copy_from_slice(id.as_bytes());
                    digest[16..18].copy_from_slice(&n.to_be_bytes());
                    sqlx::query(&format!("INSERT INTO {kind}_refresh_tokens (token_digest,family_id,issued_at_ms,spent_at_ms) VALUES ($1,$2,1,$3)"))
                        .bind(digest.as_slice()).bind(id.as_bytes().as_slice())
                        .bind((n+1<count).then_some(2_i64)).execute(pool).await.expect("token digest");
                }
                id
            }

            pub async fn count(pool: &sqlx::Pool<$db>, kind: &str, table: &str) -> i64 {
                sqlx::query_scalar(&format!("SELECT COUNT(*) FROM {kind}_refresh_{table}"))
                    .fetch_one(pool).await.expect("retained row count")
            }
        }
    };
}

backend!(sqlite, sqlx::Sqlite, 1_i64);
#[cfg(feature = "postgres-integration")]
backend!(postgres, sqlx::Postgres, true);

macro_rules! bounded_retention {
    ($store:expr,$second:expr,$backend:ident) => {{
        let store = &$store;
        let second = &$second;
        let principal = $backend::seed(store.pool()).await;
        let now = now_ms();
        for kind in ["device", "operator"] {
            $backend::family(store.pool(), principal, kind, now - 20_000, 300, false).await;
            for _ in 0..17 {
                $backend::family(store.pool(), principal, kind, now - 10_000, 1, false).await;
            }
            $backend::family(store.pool(), principal, kind, now + FAMILY_MS, 2, false).await;
            $backend::family(store.pool(), principal, kind, now + FAMILY_MS, 2, true).await;
        }
        assert_eq!(
            store.cleanup_refresh_families().await.expect("bounded first pass"),
            RefreshCleanupReport {
                device_tokens: 256,
                operator_tokens: 256,
                device_families: 0,
                operator_families: 0,
            }
        );
        for kind in ["device", "operator"] {
            assert_eq!($backend::count(store.pool(), kind, "families").await, 20);
            assert_eq!($backend::count(store.pool(), kind, "tokens").await, 65);
        }
        assert_eq!(
            store.cleanup_refresh_families().await.expect("bounded second pass"),
            RefreshCleanupReport {
                device_tokens: 59,
                operator_tokens: 59,
                device_families: 16,
                operator_families: 16,
            }
        );
        assert_eq!(
            store.cleanup_refresh_families().await.expect("remaining backlog"),
            RefreshCleanupReport {
                device_tokens: 2,
                operator_tokens: 2,
                device_families: 2,
                operator_families: 2,
            }
        );
        assert_eq!(
            store.cleanup_refresh_families().await.expect("idle pass"),
            RefreshCleanupReport::default()
        );
        for kind in ["device", "operator"] {
            assert_eq!($backend::count(store.pool(), kind, "families").await, 2);
            assert_eq!($backend::count(store.pool(), kind, "tokens").await, 4);
            let retained_spent: i64 = sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {kind}_refresh_tokens WHERE spent_at_ms IS NOT NULL"
            ))
            .fetch_one(store.pool())
            .await
            .expect("unexpired spent digests");
            assert_eq!(
                retained_spent, 2,
                "live and revoked-unexpired families retain reuse evidence"
            );
            $backend::family(store.pool(), principal, kind, now - 1, 2, false).await;
        }
        let (first, other) =
            tokio::join!(store.cleanup_refresh_families(), second.cleanup_refresh_families());
        let first = first.expect("first independent cleaner");
        let other = other.expect("second independent cleaner");
        let winner = RefreshCleanupReport {
            device_tokens: 2,
            operator_tokens: 2,
            device_families: 1,
            operator_families: 1,
        };
        assert!(
            (first == winner && other == RefreshCleanupReport::default())
                || (other == winner && first == RefreshCleanupReport::default()),
            "one independent cleaner commits the complete pass: {first:?}, {other:?}"
        );
    }};
}

macro_rules! rollback_retention {
    ($store:expr,$backend:ident,$fail:expr,$clear:expr) => {{
        let store = &$store;
        let principal = $backend::seed(store.pool()).await;
        for kind in ["device", "operator"] {
            $backend::family(store.pool(), principal, kind, now_ms() - 1, 2, false).await;
        }
        sqlx::raw_sql($fail).execute(store.pool()).await.expect("install deletion failure");
        assert_eq!(store.cleanup_refresh_families().await, Err(RefreshCleanupError::Database));
        for kind in ["device", "operator"] {
            assert_eq!($backend::count(store.pool(), kind, "families").await, 1);
            assert_eq!($backend::count(store.pool(), kind, "tokens").await, 2);
        }
        sqlx::raw_sql($clear).execute(store.pool()).await.expect("remove deletion failure");
        assert_eq!(
            store.cleanup_refresh_families().await.expect("retry known rollback"),
            RefreshCleanupReport {
                device_tokens: 2,
                operator_tokens: 2,
                device_families: 1,
                operator_families: 1,
            }
        );
    }};
}

#[tokio::test]
async fn sqlite_retention_bounds_children_and_families_preserves_live_and_serializes_pools() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-refresh-retention-{}", Uuid::now_v7()));
    let path = directory.join("store.sqlite");
    let store = SqliteStore::open(&path).await.expect("store");
    let second = SqliteStore::open(&path).await.expect("independent pool");
    bounded_retention!(store, second, sqlite);
    store.pool().close().await;
    second.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_retention_rolls_back_both_principal_kinds_on_late_failure() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-refresh-retention-{}", Uuid::now_v7()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    rollback_retention!(
        store,
        sqlite,
        "CREATE TRIGGER fail_refresh_retention BEFORE DELETE ON operator_refresh_tokens BEGIN SELECT RAISE(ABORT,'private diagnostic'); END",
        "DROP TRIGGER fail_refresh_retention"
    );
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (String, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("refresh_retention_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("isolated schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    (url.to_string(), pool, schema)
}

#[cfg(feature = "postgres-integration")]
async fn cleanup_postgres(pool: sqlx::PgPool, schema: String) {
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_bounds_children_and_families_preserves_live_and_serializes_pools() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = PostgresStore::connect(&url).await.expect("store");
    let second = PostgresStore::connect(&url).await.expect("independent pool");
    bounded_retention!(store, second, postgres);
    store.pool().close().await;
    second.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_rolls_back_both_principal_kinds_on_late_failure() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = PostgresStore::connect(&url).await.expect("store");
    rollback_retention!(
        store,
        postgres,
        "CREATE FUNCTION fail_refresh_retention() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''private diagnostic''; END'; CREATE TRIGGER fail_refresh_retention BEFORE DELETE ON operator_refresh_tokens FOR EACH ROW EXECUTE FUNCTION fail_refresh_retention()",
        "DROP TRIGGER fail_refresh_retention ON operator_refresh_tokens; DROP FUNCTION fail_refresh_retention()"
    );
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_never_reports_counts_after_lost_commit_acknowledgement() {
    use std::sync::atomic::Ordering;
    let (url, pool, schema) = postgres_fixture().await;
    let store = PostgresStore::connect(&url).await.expect("store");
    let principal = postgres::seed(store.pool()).await;
    for kind in ["device", "operator"] {
        postgres::family(store.pool(), principal, kind, now_ms() - 1, 2, false).await;
    }
    let proxy = lost_commit::LostCommitProxy::start(&url).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    proxy.armed.store(true, Ordering::SeqCst);
    assert_eq!(
        uncertain.cleanup_refresh_families().await,
        Err(RefreshCleanupError::CommitOutcomeUnknown)
    );
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    for kind in ["device", "operator"] {
        assert_eq!(postgres::count(store.pool(), kind, "families").await, 0);
        assert_eq!(postgres::count(store.pool(), kind, "tokens").await, 0);
    }
    uncertain.pool().close().await;
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_retention_rechecks_expiry_after_family_lock_wait() {
    use std::time::Duration;
    let (url, pool, schema) = postgres_fixture().await;
    let store = PostgresStore::connect(&url).await.expect("store");
    let second = PostgresStore::connect(&url).await.expect("independent pool");
    let principal = postgres::seed(store.pool()).await;
    let family = postgres::family(store.pool(), principal, "device", now_ms() - 1, 2, false).await;
    let mut blocker = store.pool().begin().await.expect("family blocker");
    let pid: i32 = sqlx::query_scalar("SELECT pg_backend_pid()")
        .fetch_one(&mut *blocker)
        .await
        .expect("blocker pid");
    sqlx::query("SELECT family_id FROM device_refresh_families WHERE family_id=$1 FOR UPDATE")
        .bind(family.as_bytes().as_slice())
        .fetch_one(&mut *blocker)
        .await
        .expect("hold family lock");
    let task = tokio::spawn(async move {
        let result = second.cleanup_refresh_families().await;
        second.pool().close().await;
        result
    });
    tokio::time::timeout(Duration::from_secs(5),async {
        loop {
            let waiting:bool=sqlx::query_scalar("SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))")
                .bind(pid).fetch_one(store.pool()).await.expect("observe family lock waiter");
            if waiting {break;}
            assert!(!task.is_finished(),"maintenance waits for family serialization");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    }).await.expect("cleanup reached family lock");
    // Model a candidate that is no longer expired when serialization completes.
    let expires = now_ms() + FAMILY_MS;
    sqlx::query(
        "UPDATE device_refresh_families SET created_at_ms=$1,expires_at_ms=$2 WHERE family_id=$3",
    )
    .bind(expires - FAMILY_MS)
    .bind(expires)
    .bind(family.as_bytes().as_slice())
    .execute(&mut *blocker)
    .await
    .expect("change locked candidate expiry");
    blocker.commit().await.expect("release family lock");
    assert_eq!(
        task.await.expect("cleaner task").expect("cleanup"),
        RefreshCleanupReport::default()
    );
    assert_eq!(postgres::count(store.pool(), "device", "families").await, 1);
    assert_eq!(postgres::count(store.pool(), "device", "tokens").await, 2);
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}
