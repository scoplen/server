// SPDX-License-Identifier: AGPL-3.0-only

mod support;

#[cfg(feature = "postgres-integration")]
use scoplen_store::account_entry_admission::{
    audit_postgres_account_entry_failure_in_transaction,
    postgres_account_entry_outcome_in_transaction,
};
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_entry_admission::{
        AccountEntryAdmissionDecision as Decision, AccountEntryEndpoint as Endpoint,
        AccountEntryFailureReason as Reason, AccountEntryPrivateBucket as Private,
        AccountEntryStateError, AccountUsernameBucket, VerifiedAccountBucket,
        audit_sqlite_account_entry_failure_in_transaction,
        sqlite_account_entry_outcome_in_transaction,
    },
    kms::KeyManagementService,
};
use std::net::IpAddr;
use uuid::Uuid;

fn source() -> IpAddr {
    "192.0.2.18".parse().expect("source")
}
const FUTURE: i64 = 4_000_000_020_000;

struct TestKms;
impl KeyManagementService for TestKms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &[7; 32]
    }
    fn backend_name(&self) -> &'static str {
        "test"
    }
}

macro_rules! quotas {
    ($first:expr,$second:expr) => {{
        let first = &$first;
        let second = &$second;
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE)
            .execute(first.pool())
            .await
            .expect("fixed database high-water");
        for endpoint in [
            Endpoint::RequestChallenge,
            Endpoint::Register,
            Endpoint::PasswordOptions,
            Endpoint::PasswordLogin,
            Endpoint::DeviceAdmission,
        ] {
            let mut tasks = Vec::new();
            for index in 0..40 {
                let store = if index % 2 == 0 { first.clone() } else { second.clone() };
                tasks.push(tokio::spawn(async move {
                    store.admit_account_entry_source(endpoint, source()).await
                }));
            }
            let mut admitted = 0;
            for task in tasks {
                match task.await.expect("task").expect("durable admission") {
                    Decision::Admitted => admitted += 1,
                    Decision::RateLimited(wait) => assert!((1..=300).contains(&wait)),
                }
            }
            assert_eq!(admitted, 30);
            assert!(matches!(
                second
                    .admit_account_entry_source(
                        endpoint,
                        "::ffff:192.0.2.18".parse().expect("mapped IP")
                    )
                    .await,
                Ok(Decision::RateLimited(_))
            ));
        }
        let device = Uuid::now_v7();
        for endpoint in [Endpoint::RequestChallenge, Endpoint::Register, Endpoint::DeviceAdmission]
        {
            for _ in 0..10 {
                assert_eq!(
                    first
                        .admit_account_entry_private(
                            endpoint,
                            source(),
                            Private::DecodedDevice(device)
                        )
                        .await
                        .expect("unknown Device debt"),
                    Decision::Admitted
                );
            }
            assert!(matches!(
                second
                    .admit_account_entry_private(endpoint, source(), Private::DecodedDevice(device))
                    .await,
                Ok(Decision::RateLimited(_))
            ));
        }
        let probe = first.ensure_account_probe_key(&TestKms).await.expect("durable Kprobe");
        let username =
            AccountUsernameBucket::new(&probe, "https://entry.example.test", "missing-user")
                .expect("canonical username");
        for endpoint in [Endpoint::PasswordOptions, Endpoint::PasswordLogin] {
            for _ in 0..10 {
                assert_eq!(
                    first
                        .admit_account_entry_private(
                            endpoint,
                            source(),
                            Private::Username(&username)
                        )
                        .await
                        .expect("unknown username debt"),
                    Decision::Admitted
                );
            }
            assert!(matches!(
                second
                    .admit_account_entry_private(endpoint, source(), Private::Username(&username))
                    .await,
                Ok(Decision::RateLimited(_))
            ));
        }
        let established =
            VerifiedAccountBucket::after_authentication(Uuid::now_v7()).expect("verified fixture");
        for endpoint in [Endpoint::Register, Endpoint::PasswordLogin, Endpoint::DeviceAdmission] {
            for _ in 0..10 {
                assert_eq!(
                    first
                        .admit_account_entry_private(
                            endpoint,
                            source(),
                            Private::EstablishedAccount(established)
                        )
                        .await
                        .expect("established debt"),
                    Decision::Admitted
                );
            }
            assert!(matches!(
                second
                    .admit_account_entry_private(
                        endpoint,
                        source(),
                        Private::EstablishedAccount(established)
                    )
                    .await,
                Ok(Decision::RateLimited(_))
            ));
        }
        assert!(matches!(
            first
                .admit_account_entry_private(
                    Endpoint::PasswordLogin,
                    source(),
                    Private::DecodedDevice(device)
                )
                .await,
            Err(AccountEntryStateError::InvalidInput)
        ));
        assert!(matches!(
            first
                .admit_account_entry_private(
                    Endpoint::RequestChallenge,
                    source(),
                    Private::EstablishedAccount(established)
                )
                .await,
            Err(AccountEntryStateError::InvalidInput)
        ));
        assert!(VerifiedAccountBucket::after_authentication(Uuid::nil()).is_err());
        let actual: i64 = sqlx::query_scalar("SELECT count(*) FROM account_entry_admission")
            .fetch_one(first.pool())
            .await
            .expect("row count");
        let retained: i64 = sqlx::query_scalar("SELECT rate_rows FROM account_entry_state")
            .fetch_one(first.pool())
            .await
            .expect("retained count");
        assert_eq!(actual, retained);
        assert_eq!(retained, 13);
    }};
}

macro_rules! cooldown {
    ($store:expr,$begin:expr,$outcome:ident,$audit:ident) => {{
        let store = &$store;
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE)
            .execute(store.pool())
            .await
            .expect("clock");
        let device = Uuid::now_v7();
        assert_eq!(
            store.admit_account_entry_source(Endpoint::Register, source()).await.expect("source"),
            Decision::Admitted
        );
        assert_eq!(
            store
                .admit_account_entry_private(
                    Endpoint::Register,
                    source(),
                    Private::DecodedDevice(device)
                )
                .await
                .expect("Device"),
            Decision::Admitted
        );
        store
            .audit_account_entry_failure(
                Endpoint::Register,
                source(),
                Reason::AuthenticationDenied,
                &[Private::DecodedDevice(device)],
            )
            .await
            .expect("denial audit and debt");
        assert_eq!(
            store.admit_account_entry_source(Endpoint::Register, source()).await.expect("cooldown"),
            Decision::RateLimited(1)
        );
        let first: Option<i64> = sqlx::query_scalar(
            "SELECT cooldown_until_ms FROM account_entry_admission WHERE endpoint=2 AND kind=1",
        )
        .fetch_one(store.pool())
        .await
        .expect("cooldown deadline");
        store
            .audit_account_entry_failure(
                Endpoint::Register,
                source(),
                Reason::AuthenticationDenied,
                &[Private::DecodedDevice(device)],
            )
            .await
            .expect("rejected cooldown does not extend debt");
        let second: Option<i64> = sqlx::query_scalar(
            "SELECT cooldown_until_ms FROM account_entry_admission WHERE endpoint=2 AND kind=1",
        )
        .fetch_one(store.pool())
        .await
        .expect("unchanged deadline");
        assert_eq!(first, second);
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE + 1000)
            .execute(store.pool())
            .await
            .expect("advance clock");
        assert_eq!(
            store
                .admit_account_entry_source(Endpoint::Register, source())
                .await
                .expect("new admitted request"),
            Decision::Admitted
        );
        let mut tx = $begin(store).await.expect("outcome transaction");
        $outcome(&mut tx, Endpoint::Register, source(), &[Private::DecodedDevice(device)], true)
            .await
            .expect("successful outcome");
        tx.commit().await.expect("commit success");
        let attempts: i64 = sqlx::query_scalar(
            "SELECT attempts FROM account_entry_admission WHERE endpoint=2 AND kind=1",
        )
        .fetch_one(store.pool())
        .await
        .expect("debt remains");
        assert_eq!(attempts, 2);
        let mut tx = $begin(store).await.expect("denial rollback transaction");
        $audit(
            &mut tx,
            Endpoint::Register,
            source(),
            Reason::AuthenticationDenied,
            &[Private::DecodedDevice(device)],
        )
        .await
        .expect("staged denial");
        tx.rollback().await.expect("rollback both debt and audit");
        let streak: i64 = sqlx::query_scalar(
            "SELECT failure_streak FROM account_entry_admission WHERE endpoint=2 AND kind=1",
        )
        .fetch_one(store.pool())
        .await
        .expect("rolled-back debt");
        assert_eq!(streak, 0);
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE + 600_000)
            .execute(store.pool())
            .await
            .expect("advance");
        assert_eq!(
            store
                .admit_account_entry_source(Endpoint::Register, source())
                .await
                .expect("new window"),
            Decision::Admitted
        );
        let count = store.cleanup_account_entry_state().await.expect("cleanup");
        assert_eq!(count.admission_rows, 1);
        let count = store.cleanup_account_entry_state().await.expect("throttled cleanup");
        assert_eq!(count.admission_rows, 0);
        assert!(matches!(
            store
                .audit_account_entry_failure(
                    Endpoint::Register,
                    source(),
                    Reason::AuthenticationDenied,
                    &[Private::DecodedDevice(Uuid::now_v7())]
                )
                .await,
            Err(AccountEntryStateError::Integrity)
        ));
    }};
}

async fn sqlite() -> (SqliteStore, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("scoplen-account-entry-{}", Uuid::now_v7()));
    (SqliteStore::open(&path.join("store.sqlite")).await.expect("SQLite"), path)
}

async fn sqlite_begin(
    store: &SqliteStore,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}

#[tokio::test]
async fn sqlite_account_entry_quotas_are_independent_and_shared_across_instances() {
    let (store, path) = sqlite().await;
    let second = SqliteStore::open(&path.join("store.sqlite")).await.expect("second pool");
    quotas!(store, second);
    second.pool().close().await;
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_account_entry_cooldown_and_audit_are_atomic_without_refunding_counts() {
    let (store, path) = sqlite().await;
    cooldown!(
        store,
        sqlite_begin,
        sqlite_account_entry_outcome_in_transaction,
        audit_sqlite_account_entry_failure_in_transaction
    );
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_account_entry_capacity_preserves_existing_debt_and_cleanup_is_bounded() {
    let (store, path) = sqlite().await;
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE)
        .execute(store.pool())
        .await
        .expect("clock");
    assert_eq!(
        store
            .admit_account_entry_source(Endpoint::Register, source())
            .await
            .expect("original debt"),
        Decision::Admitted
    );
    sqlx::query("WITH RECURSIVE rows(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM rows WHERE n<131071) INSERT INTO account_entry_admission SELECT 1,3,CAST(printf('%016d',n) AS BLOB),$1,1,0,NULL,NULL,$2,$3 FROM rows")
        .bind(FUTURE/60_000*60_000).bind(FUTURE).bind(FUTURE+600_000).execute(store.pool()).await.expect("fill fixed production ceiling");
    sqlx::query("UPDATE account_entry_state SET rate_rows=131072")
        .execute(store.pool())
        .await
        .expect("capacity metadata");
    assert_eq!(
        store
            .admit_account_entry_source(
                Endpoint::Register,
                "192.0.2.19".parse().expect("new source")
            )
            .await
            .expect("capacity denial audited"),
        Decision::RateLimited(1)
    );
    assert_eq!(
        store
            .admit_account_entry_source(Endpoint::Register, source())
            .await
            .expect("existing debt preserved"),
        Decision::Admitted
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account_entry_admission")
        .fetch_one(store.pool())
        .await
        .expect("no inserted bucket");
    assert_eq!(count, 131_072);
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE + 600_000)
        .execute(store.pool())
        .await
        .expect("expiry");
    assert_eq!(
        store.cleanup_account_entry_state().await.expect("indexed cleanup").admission_rows,
        100
    );
    assert_eq!(store.cleanup_account_entry_state().await.expect("throttled").admission_rows, 0);
    assert_eq!(
        store
            .admit_account_entry_source(Endpoint::Register, "192.0.2.19".parse().expect("source"))
            .await
            .expect("reclaimed capacity"),
        Decision::Admitted
    );
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_account_entry_failure_audit_failure_rolls_back_cooldown() {
    let (store, path) = sqlite().await;
    store.admit_account_entry_source(Endpoint::Register, source()).await.expect("source");
    let mut connection = store.pool().acquire().await.expect("failure owner");
    sqlx::raw_sql("CREATE TRIGGER fail_entry_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END").execute(&mut *connection).await.expect("install failure");
    assert!(matches!(
        store
            .audit_account_entry_failure(
                Endpoint::Register,
                source(),
                Reason::AuthenticationDenied,
                &[]
            )
            .await,
        Err(AccountEntryStateError::Audit)
    ));
    let streak: i64 = sqlx::query_scalar("SELECT failure_streak FROM account_entry_admission")
        .fetch_one(store.pool())
        .await
        .expect("rollback debt");
    assert_eq!(streak, 0);
    sqlx::raw_sql("DROP TRIGGER fail_entry_audit")
        .execute(&mut *connection)
        .await
        .expect("remove failure");
    drop(connection);
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_account_entry_corrupt_due_markers_cannot_retire_live_debt() {
    let (store, path) = sqlite().await;
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE)
        .execute(store.pool())
        .await
        .expect("clock");
    store.admit_account_entry_source(Endpoint::Register, source()).await.expect("live debt");
    assert!(
        sqlx::query("UPDATE account_entry_admission SET retire_at_ms=$1")
            .bind(FUTURE - 1)
            .execute(store.pool())
            .await
            .is_err()
    );
    let mut owner = store.pool().acquire().await.expect("owned corrupt fixture connection");
    for update in [
        "UPDATE account_entry_admission SET retire_at_ms=$1-1",
        "UPDATE account_entry_admission SET window_start_ms=$1+60000,retire_at_ms=$1-1",
        "UPDATE account_entry_admission SET failure_streak=1,last_failure_ms=$1,cooldown_until_ms=$1+1000,retire_at_ms=$1-1",
        "UPDATE account_entry_admission SET last_admitted_ms=$1+1,retire_at_ms=$1-1",
    ] {
        sqlx::query("PRAGMA ignore_check_constraints=ON")
            .execute(&mut *owner)
            .await
            .expect("inject corruption only in owned fixture");
        sqlx::query(update)
            .bind(FUTURE)
            .execute(&mut *owner)
            .await
            .expect("damaged indexed due marker");
        sqlx::query("PRAGMA ignore_check_constraints=OFF")
            .execute(&mut *owner)
            .await
            .expect("restore constraints");
        assert!(matches!(
            store.cleanup_account_entry_state().await,
            Err(AccountEntryStateError::Integrity)
        ));
        let retained: i64 = sqlx::query_scalar("SELECT rate_rows FROM account_entry_state")
            .fetch_one(store.pool())
            .await
            .expect("capacity preserved");
        let rows: i64 = sqlx::query_scalar("SELECT count(*) FROM account_entry_admission")
            .fetch_one(store.pool())
            .await
            .expect("live row preserved");
        assert_eq!(retained, 1);
        assert_eq!(rows, 1);
        sqlx::query("UPDATE account_entry_admission SET window_start_ms=$1,last_admitted_ms=$1,failure_streak=0,last_failure_ms=NULL,cooldown_until_ms=NULL,retire_at_ms=$1+600000")
            .bind(FUTURE).execute(&mut *owner).await.expect("restore real debt before next corruption");
    }
    drop(owner);
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture()
-> (scoplen_store::PostgresStore, scoplen_store::PostgresStore, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("account_entry_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let first = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("first pool");
    let second = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("second pool");
    (first, second, pool, schema)
}

#[cfg(feature = "postgres-integration")]
async fn cleanup_postgres(
    first: scoplen_store::PostgresStore,
    second: scoplen_store::PostgresStore,
    pool: sqlx::PgPool,
    schema: String,
) {
    first.pool().close().await;
    second.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_begin(
    store: &scoplen_store::PostgresStore,
) -> Result<sqlx::Transaction<'_, sqlx::Postgres>, sqlx::Error> {
    store.pool().begin().await
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_entry_quotas_are_independent_and_shared_across_instances() {
    let (first, second, pool, schema) = postgres_fixture().await;
    quotas!(first, second);
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_entry_cooldown_and_audit_are_atomic_without_refunding_counts() {
    let (first, second, pool, schema) = postgres_fixture().await;
    cooldown!(
        first,
        postgres_begin,
        postgres_account_entry_outcome_in_transaction,
        audit_postgres_account_entry_failure_in_transaction
    );
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_entry_capacity_preserves_existing_debt_and_cleanup_is_bounded() {
    let (first, second, pool, schema) = postgres_fixture().await;
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE)
        .execute(first.pool())
        .await
        .expect("clock");
    first.admit_account_entry_source(Endpoint::Register, source()).await.expect("original debt");
    sqlx::query("INSERT INTO account_entry_admission SELECT 1,3,convert_to(lpad(n::text,16,'0'),'UTF8'),$1,1,0,NULL,NULL,$2,$3 FROM generate_series(1,131070) n")
        .bind(FUTURE/60_000*60_000).bind(FUTURE).bind(FUTURE+600_000).execute(first.pool()).await.expect("fill production ceiling");
    sqlx::query("UPDATE account_entry_state SET rate_rows=131071")
        .execute(first.pool())
        .await
        .expect("capacity metadata");
    let mut tasks = Vec::new();
    for index in 0..8 {
        let store = if index % 2 == 0 { first.clone() } else { second.clone() };
        tasks.push(tokio::spawn(async move {
            store
                .admit_account_entry_source(
                    Endpoint::Register,
                    std::net::Ipv4Addr::new(192, 0, 2, 30 + index).into(),
                )
                .await
        }));
    }
    let mut wins = 0;
    for task in tasks {
        match task.await.expect("task").expect("serialized final-slot admission") {
            Decision::Admitted => wins += 1,
            Decision::RateLimited(wait) => assert_eq!(wait, 1),
        }
    }
    assert_eq!(wins, 1);
    assert_eq!(
        first
            .admit_account_entry_source(Endpoint::Register, source())
            .await
            .expect("existing debt"),
        Decision::Admitted
    );
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account_entry_admission")
        .fetch_one(first.pool())
        .await
        .expect("unchanged row count");
    assert_eq!(count, 131_072);
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE + 600_000)
        .execute(first.pool())
        .await
        .expect("expiry");
    assert_eq!(
        first.cleanup_account_entry_state().await.expect("bounded cleanup").admission_rows,
        100
    );
    assert_eq!(
        second.cleanup_account_entry_state().await.expect("shared cleanup throttle").admission_rows,
        0
    );
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_entry_failure_audit_failure_rolls_back_cooldown() {
    let (first, second, pool, schema) = postgres_fixture().await;
    first.admit_account_entry_source(Endpoint::Register, source()).await.expect("source");
    sqlx::raw_sql("CREATE FUNCTION fail_entry_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''unavailable''; END'; CREATE TRIGGER fail_entry_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_entry_audit()")
        .execute(first.pool()).await.expect("install audit failure");
    assert!(matches!(
        first
            .audit_account_entry_failure(
                Endpoint::Register,
                source(),
                Reason::AuthenticationDenied,
                &[]
            )
            .await,
        Err(AccountEntryStateError::Audit)
    ));
    let streak: i64 = sqlx::query_scalar("SELECT failure_streak FROM account_entry_admission")
        .fetch_one(first.pool())
        .await
        .expect("rollback debt");
    assert_eq!(streak, 0);
    sqlx::raw_sql("DROP TRIGGER fail_entry_audit ON deployment_audit_events; DROP FUNCTION fail_entry_audit()")
        .execute(first.pool()).await.expect("remove failure");
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_entry_constraints_reject_premature_retirement() {
    let (first, second, pool, schema) = postgres_fixture().await;
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE)
        .execute(first.pool())
        .await
        .expect("clock");
    first.admit_account_entry_source(Endpoint::Register, source()).await.expect("live debt");
    for update in [
        "UPDATE account_entry_admission SET retire_at_ms=$1-1",
        "UPDATE account_entry_admission SET window_start_ms=$1+60000,retire_at_ms=$1-1",
        "UPDATE account_entry_admission SET failure_streak=1,last_failure_ms=$1,cooldown_until_ms=$1+1000,retire_at_ms=$1-1",
        "UPDATE account_entry_admission SET last_admitted_ms=9223372036854775807,retire_at_ms=9223372036854775807-$1+$1",
    ] {
        assert!(sqlx::query(update).bind(FUTURE).execute(first.pool()).await.is_err());
    }
    assert_eq!(
        first.cleanup_account_entry_state().await.expect("live debt remains").admission_rows,
        0
    );
    let count: i64 = sqlx::query_scalar("SELECT rate_rows FROM account_entry_state")
        .fetch_one(second.pool())
        .await
        .expect("capacity unchanged");
    assert_eq!(count, 1);
    cleanup_postgres(first, second, pool, schema).await;
}
