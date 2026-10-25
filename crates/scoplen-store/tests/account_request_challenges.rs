// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
mod support;

use scoplen_api::account_admission::{
    AccountRequestChallengeRequest, AccountRequestIntent, AccountRequestKind,
};
#[cfg(feature = "postgres-integration")]
use scoplen_store::account_request_challenges::{
    claim_postgres_account_request_challenge_in_transaction as postgres_claim,
    finish_postgres_account_request_challenge_in_transaction as postgres_finish,
};
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_entry_admission::{AccountEntryEndpoint as Endpoint, AccountEntryStateError},
    account_request_challenges::{
        AccountRequestChallengeOutcome as Outcome,
        claim_sqlite_account_request_challenge_in_transaction as sqlite_claim,
        finish_sqlite_account_request_challenge_in_transaction as sqlite_finish,
    },
};
use std::net::IpAddr;
use uuid::Uuid;

const ORIGIN: &str = "https://entry.example.test";
const FUTURE: i64 = 4_000_000_020_000;
fn source() -> IpAddr {
    "192.0.2.28".parse().expect("source")
}
fn request(intent: AccountRequestIntent) -> AccountRequestChallengeRequest {
    AccountRequestChallengeRequest {
        kind: AccountRequestKind::Register,
        intent,
        operation_id: Uuid::now_v7(),
        device_id: Uuid::now_v7(),
    }
}
async fn sqlite() -> (SqliteStore, std::path::PathBuf) {
    let path = std::env::temp_dir().join(format!("scoplen-account-challenge-{}", Uuid::now_v7()));
    (SqliteStore::open(&path.join("store.sqlite")).await.expect("SQLite"), path)
}
async fn sqlite_begin(
    store: &SqliteStore,
) -> Result<sqlx::Transaction<'_, sqlx::Sqlite>, sqlx::Error> {
    store.pool().begin_with("BEGIN IMMEDIATE").await
}

macro_rules! lifecycle {
    ($store:expr,$begin:expr,$claim:ident,$finish:ident) => {{
        let store = &$store;
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE)
            .execute(store.pool())
            .await
            .expect("clock");
        store
            .admit_account_entry_source(Endpoint::RequestChallenge, source())
            .await
            .expect("HTTP source admission");
        let request = request(AccountRequestIntent::Submit);
        let issued = store
            .issue_account_request_challenge(source(), ORIGIN, &request)
            .await
            .expect("challenge");
        assert_eq!(issued.expires_at_ms, u64::try_from(FUTURE + 120_000).expect("expiry"));
        assert!(issued.attempt_id != issued.nonce);
        let attempt: Vec<u8> =
            sqlx::query_scalar("SELECT attempt_digest FROM account_request_challenges")
                .fetch_one(store.pool())
                .await
                .expect("attempt digest");
        let nonce: Vec<u8> =
            sqlx::query_scalar("SELECT nonce_digest FROM account_request_challenges")
                .fetch_one(store.pool())
                .await
                .expect("nonce digest");
        assert_eq!(attempt.len(), 32);
        assert_eq!(nonce.len(), 32);
        assert!(attempt.as_slice() != issued.attempt_id.as_ref());
        assert!(nonce.as_slice() != issued.nonce.as_ref());
        for difference in 0..5 {
            let mut wrong = request.clone();
            let mut origin = ORIGIN;
            match difference {
                0 => wrong.kind = AccountRequestKind::Admit,
                1 => wrong.intent = AccountRequestIntent::Confirm,
                2 => wrong.operation_id = Uuid::now_v7(),
                3 => wrong.device_id = Uuid::now_v7(),
                _ => origin = "https://other.example.test",
            };
            let mut tx = $begin(store).await.expect("binding transaction");
            let claim = $claim(
                &mut tx,
                origin,
                &wrong,
                issued.attempt_id.as_bytes(),
                issued.nonce.as_bytes(),
            )
            .await
            .expect("binding lookup")
            .expect("live attempt is claimed before binding authentication");
            assert!(!claim.bindings_match());
            $finish(&mut tx, claim, Outcome::Denied)
                .await
                .expect("bad binding consumes with denial audit");
            tx.rollback().await.expect("rollback consumption and denial for the next case");
        }
        let mut tx = $begin(store).await.expect("wrong nonce");
        let claim = $claim(&mut tx, ORIGIN, &request, issued.attempt_id.as_bytes(), &[0; 32])
            .await
            .expect("claim")
            .expect("matching public binding");
        assert!(!claim.nonce_matches());
        assert!(matches!(
            $finish(&mut tx, claim, Outcome::Committed).await,
            Err(AccountEntryStateError::InvalidInput)
        ));
        tx.rollback().await.expect("rollback invalid success");
        let mut tx = $begin(store).await.expect("staged denial");
        let claim = $claim(
            &mut tx,
            ORIGIN,
            &request,
            issued.attempt_id.as_bytes(),
            issued.nonce.as_bytes(),
        )
        .await
        .expect("claim")
        .expect("live");
        assert!(claim.nonce_matches());
        assert!(claim.bindings_match());
        $finish(&mut tx, claim, Outcome::Denied).await.expect("staged denial audit");
        tx.rollback().await.expect("rollback audit and consumption");
        assert!(store.deployment_audit_head().await.expect("rolled-back audit").is_none());
        let mut tx = $begin(store).await.expect("late expiry");
        let claim = $claim(
            &mut tx,
            ORIGIN,
            &request,
            issued.attempt_id.as_bytes(),
            issued.nonce.as_bytes(),
        )
        .await
        .expect("claim")
        .expect("live");
        sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
            .bind(FUTURE + 120_000)
            .execute(&mut *tx)
            .await
            .expect("waited past expiry");
        assert!(matches!(
            $finish(&mut tx, claim, Outcome::Committed).await,
            Err(AccountEntryStateError::ChallengeExpired)
        ));
        tx.rollback().await.expect("rollback all staged business state");
        let mut tx = $begin(store).await.expect("winning transaction");
        let claim = $claim(
            &mut tx,
            ORIGIN,
            &request,
            issued.attempt_id.as_bytes(),
            issued.nonce.as_bytes(),
        )
        .await
        .expect("claim")
        .expect("live");
        $finish(&mut tx, claim, Outcome::Committed).await.expect("fixed success audit");
        tx.commit().await.expect("confirmed commit");
        assert_eq!(
            store.deployment_audit_head().await.expect("audit").expect("success").sequence,
            1
        );
        let mut tx = $begin(store).await.expect("replayed request");
        assert!(
            $claim(
                &mut tx,
                ORIGIN,
                &request,
                issued.attempt_id.as_bytes(),
                issued.nonce.as_bytes()
            )
            .await
            .expect("replay lookup")
            .is_none()
        );
        tx.rollback().await.expect("no replay");
        let confirmation = crate::request(AccountRequestIntent::Confirm);
        let issued = store
            .issue_account_request_challenge(source(), ORIGIN, &confirmation)
            .await
            .expect("confirmation challenge without identity lookup");
        let mut tx = $begin(store).await.expect("confirmation transaction");
        let claim = $claim(
            &mut tx,
            ORIGIN,
            &confirmation,
            issued.attempt_id.as_bytes(),
            issued.nonce.as_bytes(),
        )
        .await
        .expect("claim")
        .expect("live");
        $finish(&mut tx, claim, Outcome::TerminalConfirmation)
            .await
            .expect("exact receipt coordinator exception");
        tx.commit().await.expect("confirmation commit");
        assert_eq!(
            store
                .deployment_audit_head()
                .await
                .expect("same audit")
                .expect("one success only")
                .sequence,
            1
        );
        let rows: i64 = sqlx::query_scalar("SELECT challenge_rows FROM account_entry_state")
            .fetch_one(store.pool())
            .await
            .expect("count");
        assert_eq!(rows, 0);
    }};
}

macro_rules! claim_race {
    ($first:expr,$second:expr,$begin:expr,$claim:ident,$finish:ident) => {{
        let first = &$first;
        let second = &$second;
        let request = request(AccountRequestIntent::Submit);
        let issued = first
            .issue_account_request_challenge(source(), ORIGIN, &request)
            .await
            .expect("challenge");
        let mut tasks = Vec::new();
        for index in 0..8 {
            let store = if index % 2 == 0 { first.clone() } else { second.clone() };
            let request = request.clone();
            let issued = issued.clone();
            tasks.push(tokio::spawn(async move {
                let mut tx = $begin(&store).await.expect("race transaction");
                let claim = $claim(
                    &mut tx,
                    ORIGIN,
                    &request,
                    issued.attempt_id.as_bytes(),
                    issued.nonce.as_bytes(),
                )
                .await
                .expect("claim");
                if let Some(claim) = claim {
                    $finish(&mut tx, claim, Outcome::Denied).await.expect("atomic denial audit");
                    tx.commit().await.expect("winning commit");
                    true
                } else {
                    tx.rollback().await.expect("loser rollback");
                    false
                }
            }));
        }
        let mut wins = 0;
        for task in tasks {
            wins += usize::from(task.await.expect("task"));
        }
        assert_eq!(wins, 1);
        assert_eq!(
            first
                .deployment_audit_head()
                .await
                .expect("audit")
                .expect("one consumed denial")
                .sequence,
            1
        );
    }};
}

#[tokio::test]
async fn sqlite_account_request_challenge_binds_digest_intent_nonce_and_atomic_outcomes() {
    let (store, path) = sqlite().await;
    lifecycle!(store, sqlite_begin, sqlite_claim, sqlite_finish);
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_account_request_challenge_is_single_use_across_independent_instances() {
    let (store, path) = sqlite().await;
    let second = SqliteStore::open(&path.join("store.sqlite")).await.expect("second instance");
    claim_race!(store, second, sqlite_begin, sqlite_claim, sqlite_finish);
    second.pool().close().await;
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_account_request_challenge_audit_failure_preserves_claim() {
    let (store, path) = sqlite().await;
    let request = request(AccountRequestIntent::Submit);
    let issued =
        store.issue_account_request_challenge(source(), ORIGIN, &request).await.expect("challenge");
    let mut connection = store.pool().acquire().await.expect("failure owner");
    sqlx::raw_sql("CREATE TRIGGER fail_challenge_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'unavailable'); END").execute(&mut *connection).await.expect("install failure");
    let mut tx = sqlite_begin(&store).await.expect("transaction");
    let claim = sqlite_claim(
        &mut tx,
        ORIGIN,
        &request,
        issued.attempt_id.as_bytes(),
        issued.nonce.as_bytes(),
    )
    .await
    .expect("claim")
    .expect("live");
    assert!(matches!(
        sqlite_finish(&mut tx, claim, Outcome::Denied).await,
        Err(AccountEntryStateError::Audit)
    ));
    tx.rollback().await.expect("rollback claim");
    let count: i64 = sqlx::query_scalar("SELECT challenge_rows FROM account_entry_state")
        .fetch_one(store.pool())
        .await
        .expect("capacity preserved");
    assert_eq!(count, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account_request_challenges")
        .fetch_one(store.pool())
        .await
        .expect("claim retained");
    assert_eq!(count, 1);
    sqlx::raw_sql("DROP TRIGGER fail_challenge_audit")
        .execute(&mut *connection)
        .await
        .expect("remove failure");
    drop(connection);
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_account_request_challenge_expiry_is_monotonic_after_restart() {
    let (store, path) = sqlite().await;
    let request = request(AccountRequestIntent::Submit);
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE)
        .execute(store.pool())
        .await
        .expect("clock");
    let issued =
        store.issue_account_request_challenge(source(), ORIGIN, &request).await.expect("challenge");
    store.pool().close().await;
    let store = SqliteStore::open(&path.join("store.sqlite")).await.expect("restart");
    let mut tx = sqlite_begin(&store).await.expect("current challenge");
    assert!(
        sqlite_claim(
            &mut tx,
            ORIGIN,
            &request,
            issued.attempt_id.as_bytes(),
            issued.nonce.as_bytes()
        )
        .await
        .expect("persisted claim")
        .is_some()
    );
    tx.rollback().await.expect("preserve");
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE + 120_000)
        .execute(store.pool())
        .await
        .expect("expiry watermark");
    let mut tx = sqlite_begin(&store).await.expect("expired claim");
    assert!(
        sqlite_claim(
            &mut tx,
            ORIGIN,
            &request,
            issued.attempt_id.as_bytes(),
            issued.nonce.as_bytes()
        )
        .await
        .expect("expiry")
        .is_none()
    );
    tx.commit().await.expect("persist high water");
    assert_eq!(
        store.cleanup_account_entry_state().await.expect("expiry cleanup").challenge_rows,
        1
    );
    let request = crate::request(AccountRequestIntent::Submit);
    let next = store
        .issue_account_request_challenge(source(), ORIGIN, &request)
        .await
        .expect("clock cannot move backwards");
    assert_eq!(next.expires_at_ms, u64::try_from(FUTURE + 240_000).expect("next expiry"));
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_account_request_challenge_capacity_is_bounded_and_reclaimed_in_batches() {
    let (store, path) = sqlite().await;
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE)
        .execute(store.pool())
        .await
        .expect("clock");
    sqlx::query("WITH RECURSIVE rows(n) AS (SELECT 1 UNION ALL SELECT n+1 FROM rows WHERE n<16384) INSERT INTO account_request_challenges SELECT CAST(printf('%032d',n) AS BLOB),zeroblob(32),zeroblob(32),1,1,zeroblob(16),zeroblob(16),$1,$2 FROM rows")
        .bind(FUTURE).bind(FUTURE+120_000).execute(store.pool()).await.expect("production challenge ceiling");
    sqlx::query("UPDATE account_entry_state SET challenge_rows=16384")
        .execute(store.pool())
        .await
        .expect("capacity count");
    assert!(matches!(
        store
            .issue_account_request_challenge(
                source(),
                ORIGIN,
                &request(AccountRequestIntent::Submit)
            )
            .await,
        Err(AccountEntryStateError::RateLimited(1))
    ));
    assert_eq!(
        store.deployment_audit_head().await.expect("audit").expect("capacity denial").sequence,
        1
    );
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE + 120_000)
        .execute(store.pool())
        .await
        .expect("expiry");
    assert_eq!(
        store.cleanup_account_entry_state().await.expect("bounded cleanup").challenge_rows,
        100
    );
    assert_eq!(
        store.cleanup_account_entry_state().await.expect("throttled cleanup").challenge_rows,
        0
    );
    store
        .issue_account_request_challenge(source(), ORIGIN, &request(AccountRequestIntent::Submit))
        .await
        .expect("reclaimed capacity");
    store.pool().close().await;
    support::remove_test_directory(path).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture()
-> (scoplen_store::PostgresStore, scoplen_store::PostgresStore, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("request_challenge_{}", Uuid::now_v7().simple());
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
async fn postgres_account_request_challenge_binds_digest_intent_nonce_and_atomic_outcomes() {
    let (first, second, pool, schema) = postgres_fixture().await;
    lifecycle!(first, postgres_begin, postgres_claim, postgres_finish);
    cleanup_postgres(first, second, pool, schema).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_request_challenge_is_single_use_across_independent_instances() {
    let (first, second, pool, schema) = postgres_fixture().await;
    claim_race!(first, second, postgres_begin, postgres_claim, postgres_finish);
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_request_challenge_capacity_and_expiry_cleanup_are_bounded() {
    let (first, second, pool, schema) = postgres_fixture().await;
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE)
        .execute(first.pool())
        .await
        .expect("clock");
    sqlx::query("INSERT INTO account_request_challenges SELECT convert_to(lpad(n::text,32,'0'),'UTF8'),decode(repeat('00',32),'hex'),decode(repeat('00',32),'hex'),1,1,decode(repeat('00',16),'hex'),decode(repeat('00',16),'hex'),$1,$2 FROM generate_series(1,16384) n")
        .bind(FUTURE).bind(FUTURE+120_000).execute(first.pool()).await.expect("production challenge ceiling");
    sqlx::query("UPDATE account_entry_state SET challenge_rows=16384")
        .execute(first.pool())
        .await
        .expect("capacity metadata");
    assert!(matches!(
        second
            .issue_account_request_challenge(
                source(),
                ORIGIN,
                &request(AccountRequestIntent::Submit)
            )
            .await,
        Err(AccountEntryStateError::RateLimited(1))
    ));
    assert_eq!(
        first.deployment_audit_head().await.expect("audit").expect("capacity denial").sequence,
        1
    );
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE + 120_000)
        .execute(first.pool())
        .await
        .expect("expiry");
    assert_eq!(
        first.cleanup_account_entry_state().await.expect("bounded cleanup").challenge_rows,
        100
    );
    assert_eq!(
        second.cleanup_account_entry_state().await.expect("shared throttle").challenge_rows,
        0
    );
    second
        .issue_account_request_challenge(source(), ORIGIN, &request(AccountRequestIntent::Submit))
        .await
        .expect("reclaimed capacity");
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_request_challenge_audit_failure_preserves_claim() {
    let (first, second, pool, schema) = postgres_fixture().await;
    let request = request(AccountRequestIntent::Submit);
    let issued =
        first.issue_account_request_challenge(source(), ORIGIN, &request).await.expect("challenge");
    sqlx::raw_sql("CREATE FUNCTION fail_challenge_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''unavailable''; END'; CREATE TRIGGER fail_challenge_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_challenge_audit()")
        .execute(first.pool()).await.expect("install audit failure");
    let mut tx = postgres_begin(&first).await.expect("transaction");
    let claim = postgres_claim(
        &mut tx,
        ORIGIN,
        &request,
        issued.attempt_id.as_bytes(),
        issued.nonce.as_bytes(),
    )
    .await
    .expect("claim")
    .expect("live");
    assert!(matches!(
        postgres_finish(&mut tx, claim, Outcome::Denied).await,
        Err(AccountEntryStateError::Audit)
    ));
    tx.rollback().await.expect("rollback claim");
    let count: i64 = sqlx::query_scalar("SELECT challenge_rows FROM account_entry_state")
        .fetch_one(second.pool())
        .await
        .expect("count");
    assert_eq!(count, 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account_request_challenges")
        .fetch_one(second.pool())
        .await
        .expect("retained challenge");
    assert_eq!(count, 1);
    sqlx::raw_sql("DROP TRIGGER fail_challenge_audit ON deployment_audit_events; DROP FUNCTION fail_challenge_audit()")
        .execute(first.pool()).await.expect("remove failure");
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_request_challenge_rechecks_expiry_after_waiting_for_the_shared_lock() {
    let (first, second, pool, schema) = postgres_fixture().await;
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE)
        .execute(first.pool())
        .await
        .expect("clock");
    let request = request(AccountRequestIntent::Submit);
    let issued =
        first.issue_account_request_challenge(source(), ORIGIN, &request).await.expect("challenge");
    let mut blocker = postgres_begin(&first).await.expect("blocking transaction");
    sqlx::query("UPDATE account_entry_state SET time_high_water_ms=$1")
        .bind(FUTURE + 120_000)
        .execute(&mut *blocker)
        .await
        .expect("lock then expire");
    let waiting = second.clone();
    let task = tokio::spawn(async move {
        let mut tx = postgres_begin(&waiting).await.expect("waiting transaction");
        let result = postgres_claim(
            &mut tx,
            ORIGIN,
            &request,
            issued.attempt_id.as_bytes(),
            issued.nonce.as_bytes(),
        )
        .await
        .expect("post-lock claim");
        tx.commit().await.expect("persist high water");
        result.is_none()
    });
    tokio::task::yield_now().await;
    blocker.commit().await.expect("release expired high water");
    assert!(task.await.expect("waiting task"));
    assert_eq!(
        first.cleanup_account_entry_state().await.expect("retire expired challenge").challenge_rows,
        1
    );
    cleanup_postgres(first, second, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_account_request_challenge_discloses_no_secret_after_unconfirmed_commit() {
    use std::sync::atomic::Ordering;
    let (first, second, pool, schema) = postgres_fixture().await;
    let mut url =
        url::Url::parse(&std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("fixture URL"))
            .expect("URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let proxy = lost_commit::LostCommitProxy::start(url.as_str()).await;
    let uncertain =
        scoplen_store::PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain
            .issue_account_request_challenge(
                source(),
                ORIGIN,
                &request(AccountRequestIntent::Submit)
            )
            .await,
        Err(AccountEntryStateError::Storage)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let count: i64 = sqlx::query_scalar("SELECT count(*) FROM account_request_challenges")
        .fetch_one(first.pool())
        .await
        .expect("committed challenge without disclosure");
    assert_eq!(count, 1);
    assert!(first.deployment_audit_head().await.expect("no business audit").is_none());
    uncertain.pool().close().await;
    cleanup_postgres(first, second, pool, schema).await;
}
