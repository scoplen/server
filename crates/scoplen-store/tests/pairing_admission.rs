// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_store::{
    RelationalStore, SqliteStore,
    pairing_admission::{
        PairingAdmissionDecision as Decision, PairingAdmissionError, PairingEndpoint as Endpoint,
        PairingFailureReason as Reason, PairingPrivateBucket as Private,
        clear_sqlite_pairing_failure_streak,
    },
};
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

fn source() -> IpAddr {
    "192.0.2.114".parse().expect("source")
}
fn millis() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
        .expect("milliseconds")
}
async fn sqlite() -> (SqliteStore, std::path::PathBuf) {
    let dir =
        std::env::temp_dir().join(format!("scoplen-pairing-admission-{}", uuid::Uuid::new_v4()));
    (SqliteStore::open(&dir.join("store.sqlite")).await.expect("SQLite"), dir)
}

macro_rules! quota_checks {
    ($first:expr,$second:expr) => {{
        let first=&$first;
        let second=&$second;
        let capability=Private::Capability([42;32]);
        let account=Private::Account(*uuid::Uuid::now_v7().as_bytes());
        first.admit_pairing_source(Endpoint::Create,source()).await.expect("seed source");
        first.admit_pairing_source(Endpoint::Read,source()).await.expect("seed source reads");
        for private in [capability,account] {
            for endpoint in [Endpoint::Read,Endpoint::Message] {
                first.admit_pairing_private(endpoint,source(),private).await.expect("seed private");
            }
        }
        // Pin a full window so wall-clock minute boundaries cannot split these quota assertions.
        let window=millis();
        sqlx::query("UPDATE pairing_admission SET window_start_ms=$1,attempts=0,retain_until_ms=$1+60000")
            .bind(window).execute(first.pool()).await.expect("stable quota fixture window");
        let mut jobs=Vec::new();
        for index in 0..40 {
            let store=if index%2==0 { first.clone() } else { second.clone() };
            jobs.push(tokio::spawn(async move { store.admit_pairing_source(Endpoint::Create,source()).await }));
        }
        let mut admitted=0;
        for job in jobs { match job.await.expect("join").expect("source admission") {
            Decision::Admitted => admitted+=1,
            Decision::RateLimited(wait) => assert!((1..=60).contains(&wait)),
        }}
        assert_eq!(admitted,30);
        assert!(matches!(second.admit_pairing_source(Endpoint::Create,"::ffff:192.0.2.114".parse().expect("mapped peer")).await,Ok(Decision::RateLimited(_))));
        assert_eq!(second.admit_pairing_source(Endpoint::Claim,source()).await.expect("independent route"),Decision::Admitted);
        for _ in 0..60 {
            assert_eq!(first.admit_pairing_private(Endpoint::Read,source(),capability).await.expect("capability read"),Decision::Admitted);
        }
        assert!(matches!(second.admit_pairing_private(Endpoint::Read,source(),capability).await,Ok(Decision::RateLimited(_))));
        for _ in 0..120 {
            assert_eq!(first.admit_pairing_private(Endpoint::Read,source(),account).await.expect("account read"),Decision::Admitted);
        }
        assert!(matches!(second.admit_pairing_private(Endpoint::Read,source(),account).await,Ok(Decision::RateLimited(_))));
        for _ in 0..120 {
            assert_eq!(first.admit_pairing_source(Endpoint::Read,source()).await.expect("source read"),Decision::Admitted);
        }
        assert!(matches!(second.admit_pairing_source(Endpoint::Read,source()).await,Ok(Decision::RateLimited(_))));
        for private in [capability,account] {
            let mut jobs=Vec::new();
            for index in 0..40 {
                let store=if index%2==0 { first.clone() } else { second.clone() };
                jobs.push(tokio::spawn(async move {
                    store.admit_pairing_private(Endpoint::Message,source(),private).await
                }));
            }
            let mut admitted=0;
            for job in jobs { match job.await.expect("join").expect("private mutation admission") {
                Decision::Admitted => admitted+=1,
                Decision::RateLimited(wait) => assert!((1..=60).contains(&wait)),
            }}
            assert_eq!(admitted,30);
            assert!(matches!(second.admit_pairing_private(Endpoint::Message,source(),private).await,Ok(Decision::RateLimited(_))));
        }
        assert!(matches!(first.admit_pairing_private(Endpoint::Claim,source(),capability).await,Err(PairingAdmissionError::InvalidInput)));
        assert!(matches!(first.admit_pairing_private(Endpoint::Create,source(),account).await,Err(PairingAdmissionError::InvalidInput)));
        let old_tables:i64=sqlx::query_scalar("SELECT (SELECT COUNT(*) FROM personal_admission)+(SELECT COUNT(*) FROM device_auth_admission)+(SELECT COUNT(*) FROM operator_auth_admission)")
            .fetch_one(first.pool()).await.expect("independent admission");
        assert_eq!(old_tables,0);
    }};
}

macro_rules! failure_checks {
    ($store:expr,$fail:expr,$unfail:expr,$clear:ident) => {{
        let store=&$store;
        let private=Private::Capability([11;32]);
        let endpoint=Endpoint::Message;
        store.admit_pairing_source(endpoint,source()).await.expect("source");
        store.admit_pairing_private(endpoint,source(),private).await.expect("private");
        store.audit_pairing_failure(endpoint,Reason::PairingDenied,source(),Some(private)).await.expect("denial");
        let before:Vec<(i64,i64,i64,Option<i64>)>=sqlx::query_as("SELECT kind,attempts,failure_streak,cooldown_until_ms FROM pairing_admission ORDER BY kind")
            .fetch_all(store.pool()).await.expect("before");
        assert_eq!(before.len(),2);
        assert!(before.iter().all(|r|r.1==1 && r.2==1 && r.3.is_some()));
        // Another request admitted before the first denial may arrive while its cooldown is active.
        store.audit_pairing_failure(endpoint,Reason::PairingDenied,source(),Some(private)).await.expect("concurrent denial");
        store.audit_pairing_failure(endpoint,Reason::RateLimited,source(),Some(private)).await.expect("limited audit");
        let after:Vec<(i64,i64,i64,Option<i64>)>=sqlx::query_as("SELECT kind,attempts,failure_streak,cooldown_until_ms FROM pairing_admission ORDER BY kind")
            .fetch_all(store.pool()).await.expect("after");
        assert_eq!(before,after,"cooldown and counts cannot extend on a rejection");
        sqlx::query("UPDATE pairing_admission SET cooldown_until_ms=0").execute(store.pool()).await.expect("elapse cooldown");
        sqlx::raw_sql($fail).execute(store.pool()).await.expect("inject audit failure");
        assert!(matches!(store.audit_pairing_failure(endpoint,Reason::PairingDenied,source(),Some(private)).await,Err(PairingAdmissionError::Audit)));
        let streaks:Vec<i64>=sqlx::query_scalar("SELECT failure_streak FROM pairing_admission ORDER BY kind").fetch_all(store.pool()).await.expect("rollback");
        assert_eq!(streaks,vec![1,1]);
        sqlx::raw_sql($unfail).execute(store.pool()).await.expect("remove failure");
        store.audit_pairing_failure(endpoint,Reason::PairingDenied,source(),Some(private)).await.expect("second admitted denial");
        assert!(matches!(store.admit_pairing_private(endpoint,source(),private).await,Ok(Decision::RateLimited(2))));
        let mut tx=store.pool().begin().await.expect("business transaction");
        $clear(&mut tx,source(),endpoint,private).await.expect("transactional clear");
        tx.rollback().await.expect("business rollback");
        let streaks:Vec<i64>=sqlx::query_scalar("SELECT failure_streak FROM pairing_admission ORDER BY kind").fetch_all(store.pool()).await.expect("rollback clear");
        assert_eq!(streaks,vec![2,2]);
        let mut tx=store.pool().begin().await.expect("business transaction");
        $clear(&mut tx,source(),endpoint,private).await.expect("successful clear");
        tx.commit().await.expect("commit success");
        let counts:Vec<(i64,i64)>=sqlx::query_as("SELECT attempts,failure_streak FROM pairing_admission ORDER BY kind").fetch_all(store.pool()).await.expect("counts");
        assert_eq!(counts,vec![(1,0),(1,0)]);
        store.audit_pairing_failure(endpoint,Reason::PairingDenied,source(),None).await.expect("unverified source-only denial");
        let streaks:Vec<i64>=sqlx::query_scalar("SELECT failure_streak FROM pairing_admission ORDER BY kind").fetch_all(store.pool()).await.expect("source only");
        assert_eq!(streaks,vec![1,0]);
        sqlx::query("UPDATE pairing_admission SET last_failure_ms=$1,cooldown_until_ms=0").bind(millis()-600_001).execute(store.pool()).await.expect("idle fixture");
        assert_eq!(store.admit_pairing_source(endpoint,source()).await.expect("idle clears"),Decision::Admitted);
        let events:Vec<Vec<u8>>=sqlx::query_scalar("SELECT event_bytes FROM deployment_audit_events").fetch_all(store.pool()).await.expect("safe events");
        assert_eq!(events.len(),5);
        for event in events { assert_eq!(event.len(),b"spl-pairing-failure-v1".len()+10,"only endpoint,reason,time"); }
        store.verify_deployment_audit_chain().await.expect("audit chain");
        // When a private rejection has a shorter cooldown, report the exhausted source window.
        sqlx::query("UPDATE pairing_admission SET window_start_ms=$1,attempts=30,last_failure_ms=NULL,cooldown_until_ms=NULL WHERE kind=1")
            .bind(millis()).execute(store.pool()).await.expect("source window");
        sqlx::query("UPDATE pairing_admission SET window_start_ms=$1,attempts=0,last_failure_ms=$1,failure_streak=1,cooldown_until_ms=$1+5000 WHERE kind=2")
            .bind(millis()).execute(store.pool()).await.expect("private cooldown");
        assert!(matches!(store.admit_pairing_private(endpoint,source(),private).await,Ok(Decision::RateLimited(59..=60))));
        sqlx::query("UPDATE pairing_admission SET cooldown_until_ms=$1+300000 WHERE kind=2")
            .bind(millis()).execute(store.pool()).await.expect("greater concurrent cooldown");
        assert_eq!(store.pairing_retry_after(endpoint,source(),Some(private),60).await.expect("greatest resource wait"),300);
        let attempts:Vec<i64>=sqlx::query_scalar("SELECT attempts FROM pairing_admission ORDER BY kind")
            .fetch_all(store.pool()).await.expect("retry lookup preserves counts");
        assert_eq!(attempts,vec![30,0]);
    }};
}

#[tokio::test]
async fn sqlite_quotas_are_durable_and_independent_across_replicas() {
    let (store, dir) = sqlite().await;
    let replica = SqliteStore::open(&dir.join("store.sqlite")).await.expect("replica");
    quota_checks!(store, replica);
    store.pool().close().await;
    replica.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_denial_audit_success_and_maximum_wait_are_atomic() {
    let (store, dir) = sqlite().await;
    failure_checks!(
        store,
        "CREATE TRIGGER deny_pairing_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'fixture failure'); END",
        "DROP TRIGGER deny_pairing_audit",
        clear_sqlite_pairing_failure_streak
    );
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_cleanup_is_bounded_and_unavailable_storage_fails_closed() {
    let (store, dir) = sqlite().await;
    for suffix in 0..40_u8 {
        store
            .admit_pairing_source(Endpoint::Read, IpAddr::from([198, 51, 100, suffix]))
            .await
            .expect("seed");
    }
    sqlx::query("UPDATE pairing_admission SET retain_until_ms=1")
        .execute(store.pool())
        .await
        .expect("expired fixture");
    store.admit_pairing_source(Endpoint::Create, source()).await.expect("bounded cleanup");
    let remaining: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM pairing_admission WHERE retain_until_ms=1")
            .fetch_one(store.pool())
            .await
            .expect("remaining");
    assert_eq!(remaining, 24);
    store.pool().close().await;
    assert!(matches!(
        store.admit_pairing_source(Endpoint::Read, source()).await,
        Err(PairingAdmissionError::Database)
    ));
    support::remove_test_directory(dir).await;
}

#[tokio::test]
async fn sqlite_failed_success_clear_rolls_back_its_business_transaction() {
    let (store, dir) = sqlite().await;
    let private = Private::Capability([18; 32]);
    store.admit_pairing_source(Endpoint::Read, source()).await.expect("source");
    store.admit_pairing_private(Endpoint::Read, source(), private).await.expect("private");
    store
        .audit_pairing_failure(Endpoint::Read, Reason::PairingDenied, source(), Some(private))
        .await
        .expect("denial");
    sqlx::raw_sql("CREATE TABLE pairing_business_probe (value INTEGER NOT NULL); CREATE TRIGGER deny_pairing_clear BEFORE UPDATE ON pairing_admission WHEN OLD.kind=2 BEGIN SELECT RAISE(ABORT,'fixture failure'); END")
        .execute(store.pool()).await.expect("clear failure fixture");
    let mut tx = store.pool().begin_with("BEGIN IMMEDIATE").await.expect("business transaction");
    sqlx::query("INSERT INTO pairing_business_probe VALUES (1)")
        .execute(&mut *tx)
        .await
        .expect("business mutation");
    assert!(matches!(
        clear_sqlite_pairing_failure_streak(&mut tx, source(), Endpoint::Read, private).await,
        Err(PairingAdmissionError::Database)
    ));
    tx.rollback().await.expect("roll back business and partial clear");
    let business: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing_business_probe")
        .fetch_one(store.pool())
        .await
        .expect("business rollback");
    assert_eq!(business, 0);
    let streaks: Vec<i64> =
        sqlx::query_scalar("SELECT failure_streak FROM pairing_admission ORDER BY kind")
            .fetch_all(store.pool())
            .await
            .expect("clear rollback");
    assert_eq!(streaks, vec![1, 1]);
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_quotas_audit_and_success_across_replicas() {
    use scoplen_store::pairing_admission::clear_postgres_pairing_failure_streak;
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("disposable PG fixture");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("pairing_admission_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("store");
    let replica = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("replica");
    quota_checks!(store, replica);
    sqlx::query("DELETE FROM pairing_admission")
        .execute(store.pool())
        .await
        .expect("clear owned fixture");
    failure_checks!(
        store,
        "CREATE FUNCTION deny_pairing_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END; $$; CREATE TRIGGER deny_pairing_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION deny_pairing_audit()",
        "DROP TRIGGER deny_pairing_audit ON deployment_audit_events; DROP FUNCTION deny_pairing_audit()",
        clear_postgres_pairing_failure_streak
    );
    replica.pool().close().await;
    store.pool().close().await;
    assert!(
        schema.starts_with("pairing_admission_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned fixture");
    pool.close().await;
}
