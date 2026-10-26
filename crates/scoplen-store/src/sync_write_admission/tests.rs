// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use crate::test_support as support;
use SyncWriteAdmissionDecision::{Admitted, PolicyPending, RateLimited};

fn limits(rate: u64, burst: u64) -> WriteRateLimits {
    WriteRateLimits::new(rate, burst).expect("positive limits")
}

#[test]
fn fractional_refill_clock_transitions_and_unsigned_boundaries() {
    assert!(WriteRateLimits::new(0, 1).unwrap_err().contains("write_requests_per_second"));
    assert!(WriteRateLimits::new(1, 0).unwrap_err().contains("write_burst"));
    let policy = limits(2, 3);
    let mut bucket = Bucket::fresh(policy);
    for _ in 0..3 {
        assert_eq!(bucket.admit(policy, TOKEN_SCALE, 0).unwrap(), Admitted);
    }
    assert_eq!(bucket.admit(policy, TOKEN_SCALE, 0).unwrap(), RateLimited(1));
    assert_eq!(bucket.admit(policy, TOKEN_SCALE + TOKEN_SCALE / 4, 0).unwrap(), RateLimited(1));
    assert_eq!(bucket.tokens, TOKEN_SCALE / 2);
    assert_eq!(bucket.admit(policy, TOKEN_SCALE + TOKEN_SCALE / 2, 0).unwrap(), Admitted);
    let retirement = bucket.retire_at().unwrap();
    assert_eq!(bucket.admit(policy, 0, 0).unwrap(), RateLimited(2));
    assert_eq!(bucket.retire_at().unwrap(), retirement, "denial/rollback cannot extend debt");
    assert_eq!(bucket.admit(limits(1, 1), 2 * TOKEN_SCALE, 0).unwrap(), PolicyPending);
    assert_eq!(bucket.admit(limits(1, 1), 3 * TOKEN_SCALE, 0).unwrap(), Admitted);
    assert_eq!(bucket.admit(policy, 3 * TOKEN_SCALE, 0).unwrap(), PolicyPending);

    let maximum = limits(u64::MAX, u64::MAX);
    assert_eq!(maximum.requests_per_second(), u64::MAX);
    assert_eq!(maximum.burst(), u64::MAX);
    let mut fast = Bucket::fresh(limits(u64::MAX, 1));
    assert_eq!(fast.admit(fast.limits, 0, 0).unwrap(), Admitted);
    assert_eq!(fast.admit(fast.limits, 0, 0).unwrap(), RateLimited(1));
    assert_eq!(fast.admit(fast.limits, 1, 0).unwrap(), Admitted);
    assert_eq!(fast.admit(fast.limits, u128::MAX - IDLE_GRACE - 2, 0).unwrap(), Admitted);
    let mut slow = Bucket { limits: limits(1, u64::MAX), tokens: 0, origin: 0 };
    assert!(slow.retire_at().unwrap() > u128::try_from(i64::MAX).unwrap());
    assert_eq!(slow.admit(slow.limits, u128::MAX - IDLE_GRACE - TOKEN_SCALE, 0).unwrap(), Admitted);
    assert!(slow.admit(slow.limits, u128::MAX, 0).is_err(), "unsafe horizon fails closed");
}

macro_rules! store_checks {
    ($first:expr, $second:expr) => {{
        let first = &$first;
        let second = &$second;
        let now = 1_000_000_000 * TOKEN_SCALE;
        let policy = limits(2, 3);
        let device = [1; 16];
        let mut tasks = Vec::new();
        for index in 0..12 {
            let store = if index % 2 == 0 { (*first).clone() } else { (*second).clone() };
            tasks.push(tokio::spawn(async move {
                store.admit_sync_write_with_clock(device, policy, Clock::Fixed(now)).await
            }));
        }
        let mut count = 0;
        for task in tasks {
            match task.await.expect("admission task").expect("serialized admission") {
                Admitted => count += 1,
                RateLimited(1) => {},
                other => panic!("unexpected decision {other:?}"),
            }
        }
        assert_eq!(count, 3, "one burst across independent pools and first insertion");
        assert_eq!(second.admit_sync_write_with_clock([2;16], policy, Clock::Fixed(now)).await.unwrap(), Admitted);
        assert_eq!(second.admit_sync_write_with_clock(device, policy, Clock::Fixed(now + TOKEN_SCALE/4)).await.unwrap(), RateLimited(1));
        assert_eq!(first.admit_sync_write_with_clock(device, policy, Clock::Fixed(now + TOKEN_SCALE/2)).await.unwrap(), Admitted);
        assert_eq!(second.admit_sync_write_with_clock(device, limits(1,1), Clock::Fixed(now + TOKEN_SCALE/2)).await.unwrap(), PolicyPending);
        assert_eq!(first.admit_sync_write_with_clock(device, limits(1,1), Clock::Fixed(now + 2*TOKEN_SCALE)).await.unwrap(), Admitted);
        assert_eq!(second.admit_sync_write_with_clock(device, policy, Clock::Fixed(now + 2*TOKEN_SCALE)).await.unwrap(), PolicyPending);

        let maximum = limits(u64::MAX,u64::MAX);
        first.admit_sync_write_with_clock([3;16],maximum,Clock::Fixed(now)).await.unwrap();
        let row = sqlx::query_as::<_,StoredBucket>("SELECT device_id,requests_per_second,burst,tokens,refill_origin_ns,retire_at_ns FROM sync_write_admission WHERE device_id=$1")
            .bind([3_u8;16].as_slice()).fetch_one(first.pool()).await.unwrap();
        assert_eq!(Bucket::decode(&row).unwrap().limits,maximum);
        assert_eq!(Bucket::decode(&row).unwrap().tokens, maximum.capacity()-TOKEN_SCALE);

        // The failed response follows a real committed counter change; it is never retried.
        assert!(first.admit_sync_write_with_clock([4;16],limits(1,1),Clock::LostCommit(now)).await.is_err());
        assert_eq!(second.admit_sync_write_with_clock([4;16],limits(1,1),Clock::Fixed(now)).await.unwrap(),RateLimited(1));

        sqlx::query("DELETE FROM sync_write_admission").execute(first.pool()).await.unwrap();
        for index in 10_u8..33 {
            first.admit_sync_write_with_clock([index;16],limits(1,1),Clock::Fixed(now)).await.unwrap();
        }
        let cleanup = now + 61*TOKEN_SCALE;
        first.admit_sync_write_with_clock([50;16],limits(1,1),Clock::Fixed(cleanup-1)).await.unwrap();
        let before: i64=sqlx::query_scalar("SELECT COUNT(*) FROM sync_write_admission").fetch_one(first.pool()).await.unwrap();
        assert_eq!(before,24,"not yet fully refilled plus 60 seconds");
        second.admit_sync_write_with_clock([51;16],limits(1,1),Clock::Fixed(cleanup)).await.unwrap();
        let remaining: Vec<Vec<u8>>=sqlx::query_scalar("SELECT device_id FROM sync_write_admission ORDER BY retire_at_ns,device_id").fetch_all(first.pool()).await.unwrap();
        assert_eq!(remaining.len(),9,"exactly 16 retired from 23 eligible rows");
        assert_eq!(remaining[0],vec![26;16],"equal-time candidates retain key order");
        // Cleanup validates indexed candidates instead of deleting a corrupt depleted row.
        sqlx::query("UPDATE sync_write_admission SET tokens=$1 WHERE device_id=$2")
            .bind(u128::MAX.to_be_bytes().as_slice()).bind([26_u8;16].as_slice()).execute(first.pool()).await.unwrap();
        assert!(matches!(first.admit_sync_write_with_clock([60;16],limits(1,1),Clock::Fixed(cleanup)).await,Err(SyncWriteAdmissionError::InvalidState)));
        let inserted: i64=sqlx::query_scalar("SELECT COUNT(*) FROM sync_write_admission WHERE device_id=$1").bind([60_u8;16].as_slice()).fetch_one(first.pool()).await.unwrap();
        assert_eq!(inserted,0,"failed cleanup rolls back the current charge");
        sqlx::query("UPDATE sync_write_admission SET tokens=$1 WHERE device_id=$2")
            .bind(0_u128.to_be_bytes().as_slice()).bind([26_u8;16].as_slice()).execute(first.pool()).await.unwrap();
        let watermark: Vec<u8>=sqlx::query_scalar(WATERMARK).fetch_one(first.pool()).await.unwrap();
        assert_eq!(u128::from_be_bytes(unsigned(&watermark).unwrap()),cleanup);
        assert_eq!(first.admit_sync_write_with_clock([10;16],limits(1,1),Clock::Fixed(now-TOKEN_SCALE)).await.unwrap(),Admitted);
        assert_eq!(second.admit_sync_write_with_clock([10;16],limits(1,1),Clock::Fixed(now-TOKEN_SCALE)).await.unwrap(),RateLimited(63));
        assert_eq!(second.admit_sync_write_with_clock([10;16],limits(1,1),Clock::Fixed(cleanup)).await.unwrap(),RateLimited(1));
        assert_eq!(first.admit_sync_write_with_clock([10;16],limits(1,1),Clock::Fixed(cleanup+TOKEN_SCALE)).await.unwrap(),Admitted);

        let race_now=cleanup+2*TOKEN_SCALE;
        first.admit_sync_write_with_clock([70;16],limits(1,1),Clock::Fixed(race_now)).await.unwrap();
        let (changed,old)=tokio::join!(
            first.admit_sync_write_with_clock([70;16],limits(2,1),Clock::Fixed(race_now-TOKEN_SCALE)),
            second.admit_sync_write_with_clock([70;16],limits(1,1),Clock::Fixed(race_now)));
        assert_eq!(changed.unwrap(),PolicyPending);
        assert_eq!(old.unwrap(),RateLimited(1));
        let (changed,old)=tokio::join!(
            first.admit_sync_write_with_clock([70;16],limits(2,1),Clock::Fixed(race_now+10*TOKEN_SCALE)),
            second.admit_sync_write_with_clock([70;16],limits(1,1),Clock::Fixed(race_now)));
        assert_eq!(changed.unwrap(),Admitted);
        assert!(matches!(old.unwrap(),RateLimited(1)|PolicyPending));
        let (retire,recreate)=tokio::join!(
            first.admit_sync_write_with_clock([71;16],limits(1,1),Clock::Fixed(race_now+71*TOKEN_SCALE)),
            second.admit_sync_write_with_clock([70;16],limits(1,1),Clock::Fixed(race_now)));
        assert_eq!(retire.unwrap(),Admitted);
        assert!(matches!(recreate.unwrap(),Admitted|PolicyPending));
        let mut grants=0;
        for _ in 0..2 {
            if first.admit_sync_write_with_clock([70;16],limits(1,1),Clock::Fixed(race_now)).await.unwrap()==Admitted {grants+=1;}
        }
        assert!(grants<=1,"cleanup/clock/policy race cannot grant repeated recreated refill");
        sqlx::query("UPDATE sync_write_admission_clock SET retired_through_ns=$1")
            .bind(u128::MAX.to_be_bytes().as_slice()).execute(first.pool()).await.unwrap();
        assert!(matches!(second.admit_sync_write([61;16],limits(1,1)).await,Err(SyncWriteAdmissionError::InvalidState)),"unsafe watermark horizon fails closed");
        sqlx::query("DELETE FROM sync_write_admission_clock").execute(first.pool()).await.unwrap();
        assert!(second.admit_sync_write([61;16],limits(1,1)).await.is_err(),"missing watermark fails closed");
    }};
}

#[tokio::test]
async fn sqlite_independent_pools_clock_policy_cleanup_and_unknown_commit() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-write-admission-{}", uuid::Uuid::new_v4()));
    let path = directory.join("store.sqlite");
    let first = SqliteStore::open(&path).await.unwrap();
    let second = SqliteStore::open(&path).await.unwrap();
    let mut tx = first.pool().begin().await.unwrap();
    assert_eq!(sqlite_now(&mut tx).await.unwrap() % 1_000_000, 0, "SQLite millisecond precision");
    tx.rollback().await.unwrap();
    store_checks!(first, second);
    first.pool().close().await;
    second.pool().close().await;
    support::remove_test_directory(directory).await;
}

macro_rules! suppressed_mutation_checks {
    ($store:expr, $postgres:expr) => {{
        let store = &$store;
        // Reusing one DDL connection keeps SQLite's schema cache current across trigger replacement.
        let mut fault_connection = store.pool().acquire().await.unwrap();
        let now = 1_000_000_000 * TOKEN_SCALE;
        for (table, event) in [
            ("sync_write_admission", "UPDATE OF tokens"),
            ("sync_write_admission", "DELETE"),
            ("sync_write_admission_clock", "UPDATE OF retired_through_ns"),
        ] {
            sqlx::query("DELETE FROM sync_write_admission").execute(store.pool()).await.unwrap();
            store.admit_sync_write_with_clock([1;16],limits(1,1),Clock::Fixed(now)).await.unwrap();
            let create = if $postgres {
                format!("CREATE FUNCTION suppress_admission_mutation() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$; CREATE TRIGGER suppress_admission_mutation BEFORE {event} ON {table} FOR EACH ROW EXECUTE FUNCTION suppress_admission_mutation()")
            } else {
                format!("CREATE TRIGGER suppress_admission_mutation BEFORE {event} ON {table} BEGIN SELECT RAISE(IGNORE); END")
            };
            sqlx::raw_sql(&create).execute(&mut *fault_connection).await.unwrap();
            assert!(matches!(
                store.admit_sync_write_with_clock([2;16],limits(1,1),Clock::Fixed(now+61*TOKEN_SCALE)).await,
                Err(SyncWriteAdmissionError::InvalidState)
            ), "suppressed {event} on {table} must fail closed");
            let devices: Vec<Vec<u8>> = sqlx::query_scalar("SELECT device_id FROM sync_write_admission ORDER BY device_id")
                .fetch_all(store.pool()).await.unwrap();
            assert_eq!(devices, vec![vec![1;16]], "current admission and retirement both roll back");
            let watermark: Vec<u8> = sqlx::query_scalar(WATERMARK).fetch_one(store.pool()).await.unwrap();
            assert_eq!(watermark, vec![0;16], "no retirement watermark may commit");
            let drop = if $postgres {
                format!("DROP TRIGGER suppress_admission_mutation ON {table}; DROP FUNCTION suppress_admission_mutation()")
            } else {
                "DROP TRIGGER suppress_admission_mutation".to_owned()
            };
            sqlx::raw_sql(&drop).execute(&mut *fault_connection).await.unwrap();
        }
    }};
}

#[tokio::test]
async fn sqlite_suppressed_mutations_fail_closed_and_roll_back() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-admission-mutations-{}", uuid::Uuid::new_v4()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.unwrap();
    suppressed_mutation_checks!(store, false);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (PostgresStore, PostgresStore, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("owned PostgreSQL fixture");
    let pool = sqlx::PgPool::connect(&database).await.unwrap();
    let schema = format!("write_admission_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.unwrap();
    let mut url = url::Url::parse(&database).unwrap();
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    (
        PostgresStore::connect(url.as_str()).await.unwrap(),
        PostgresStore::connect(url.as_str()).await.unwrap(),
        pool,
        schema,
    )
}

#[cfg(feature = "postgres-integration")]
async fn cleanup_postgres(
    first: PostgresStore,
    second: PostgresStore,
    pool: sqlx::PgPool,
    schema: String,
) {
    first.pool().close().await;
    second.pool().close().await;
    assert!(
        schema.starts_with("write_admission_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE")).execute(&pool).await.unwrap();
    pool.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_independent_pools_clock_policy_cleanup_and_unknown_commit() {
    let (first, second, pool, schema) = postgres_fixture().await;
    let mut tx = first.pool().begin().await.unwrap();
    assert_eq!(postgres_now(&mut tx).await.unwrap() % 1_000, 0, "PostgreSQL microsecond precision");
    tx.rollback().await.unwrap();
    store_checks!(first, second);
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_suppressed_mutations_fail_closed_and_roll_back() {
    let (first, second, pool, schema) = postgres_fixture().await;
    suppressed_mutation_checks!(first, true);
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_locked_candidates_are_bounded_and_other_devices_progress() {
    let (first, second, pool, schema) = postgres_fixture().await;
    let now = 1_000_000_000 * TOKEN_SCALE;
    for index in 1..=20 {
        first
            .admit_sync_write_with_clock([index; 16], limits(1, 1), Clock::Fixed(now))
            .await
            .unwrap();
    }
    let mut blocker = first.pool().begin().await.unwrap();
    let blocker_pid: i32 =
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *blocker).await.unwrap();
    sqlx::query("SELECT device_id FROM sync_write_admission WHERE device_id <= $1 ORDER BY device_id FOR UPDATE")
        .bind([16_u8;16].as_slice()).fetch_all(&mut *blocker).await.unwrap();
    let pending = {
        let store = second.clone();
        tokio::spawn(async move {
            store.admit_sync_write_with_clock([1; 16], limits(1, 1), Clock::Fixed(now)).await
        })
    };
    tokio::time::timeout(std::time::Duration::from_secs(10), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker_pid)
            .fetch_one(second.pool())
            .await
            .unwrap();
            if waiting {
                break;
            }
            tokio::time::sleep(std::time::Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("same-device admission reaches its row lock");
    tokio::time::timeout(
        std::time::Duration::from_secs(5),
        second.admit_sync_write_with_clock(
            [30; 16],
            limits(1, 1),
            Clock::Fixed(now + 61 * TOKEN_SCALE),
        ),
    )
    .await
    .expect("another device must progress")
    .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_write_admission")
        .fetch_one(second.pool())
        .await
        .unwrap();
    assert_eq!(count, 21, "16 locked candidates do not cause scanning replacements 17..20");
    let watermark: Vec<u8> = sqlx::query_scalar(WATERMARK).fetch_one(second.pool()).await.unwrap();
    assert_eq!(watermark, vec![0; 16], "no deletion means no global watermark write");
    assert!(!pending.is_finished(), "same-device admission remains blocked");
    blocker.rollback().await.unwrap();
    assert_eq!(pending.await.unwrap().unwrap(), RateLimited(1));
    second
        .admit_sync_write_with_clock([31; 16], limits(1, 1), Clock::Fixed(now + 61 * TOKEN_SCALE))
        .await
        .unwrap();
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM sync_write_admission")
        .fetch_one(second.pool())
        .await
        .unwrap();
    assert_eq!(count, 6, "cleanup after lock release remains capped at 16");
    cleanup_postgres(first, second, pool, schema).await;
}
