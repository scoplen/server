// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use scoplen_crypto::{DpopProof, DpopTarget, DpopToken, P256SigningKey, dpop_jwk_thumbprint};
use scoplen_store::{
    RelationalStore, SqliteStore,
    operator_admission::{
        OperatorAdmissionDecision as Decision, OperatorAdmissionError,
        OperatorAuthEndpoint as Endpoint, OperatorAuthFailureReason as Reason,
        OperatorPrivateBucket as Private,
    },
};
use sqlx::Row;
use std::{
    net::IpAddr,
    time::{SystemTime, UNIX_EPOCH},
};

fn source() -> IpAddr {
    "192.0.2.80".parse().expect("source")
}
fn millis() -> i64 {
    i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
        .expect("time")
}
async fn sqlite() -> (SqliteStore, std::path::PathBuf) {
    let dir =
        std::env::temp_dir().join(format!("scoplen-operator-admission-{}", uuid::Uuid::new_v4()));
    (SqliteStore::open(&dir.join("store.sqlite")).await.expect("SQLite"), dir)
}

macro_rules! quotas {
    ($first:expr,$second:expr) => {{
        let first = &$first;
        let second = &$second;
        let mut jobs = Vec::new();
        for index in 0..40 {
            let store = if index % 2 == 0 { first.clone() } else { second.clone() };
            jobs.push(tokio::spawn(async move {
                store.admit_operator_auth_source(Endpoint::SetupOptions, source()).await
            }));
        }
        let mut admitted = 0;
        for job in jobs {
            match job.await.expect("join").expect("admission") {
                Decision::Admitted => admitted += 1,
                Decision::RateLimited(wait) => assert!((1..=60).contains(&wait)),
            }
        }
        assert_eq!(admitted, 30);
        assert!(matches!(
            second
                .admit_operator_auth_source(
                    Endpoint::SetupOptions,
                    "::ffff:192.0.2.80".parse().expect("mapped source")
                )
                .await,
            Ok(Decision::RateLimited(_))
        ));
        assert_eq!(
            second
                .admit_operator_auth_source(Endpoint::SetupFinish, source())
                .await
                .expect("separate endpoint"),
            Decision::Admitted
        );
        let digest = [9; 32];
        for _ in 0..5 {
            assert_eq!(
                first
                    .admit_operator_auth_private(
                        Endpoint::SetupOptions,
                        Private::SetupDigest(&digest)
                    )
                    .await
                    .expect("nonexistent digest admitted"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_private(Endpoint::SetupOptions, Private::SetupDigest(&digest))
                .await,
            Ok(Decision::RateLimited(_))
        ));
        assert_eq!(
            second
                .admit_operator_auth_private(Endpoint::SetupFinish, Private::SetupDigest(&digest))
                .await
                .expect("separate digest endpoint"),
            Decision::Admitted
        );
        let ceremony = uuid::Uuid::now_v7();
        for _ in 0..5 {
            assert_eq!(
                first
                    .admit_operator_auth_private(Endpoint::LoginFinish, Private::Ceremony(ceremony))
                    .await
                    .expect("nonexistent ceremony admitted"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_private(Endpoint::LoginFinish, Private::Ceremony(ceremony))
                .await,
            Ok(Decision::RateLimited(_))
        ));
        let operator = uuid::Uuid::now_v7();
        for _ in 0..10 {
            assert_eq!(
                first
                    .admit_operator_auth_private(
                        Endpoint::LoginFinish,
                        Private::AuthenticatedOperator(operator)
                    )
                    .await
                    .expect("verified operator admission"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_private(
                    Endpoint::LoginFinish,
                    Private::AuthenticatedOperator(operator)
                )
                .await,
            Ok(Decision::RateLimited(_))
        ));
        assert_eq!(
            second
                .admit_operator_auth_private(
                    Endpoint::Refresh,
                    Private::AuthenticatedOperator(operator)
                )
                .await
                .expect("separate refresh window"),
            Decision::Admitted
        );
        for _ in 0..10 {
            assert_eq!(
                first
                    .admit_operator_auth_private(
                        Endpoint::Logout,
                        Private::AuthenticatedOperator(operator)
                    )
                    .await
                    .expect("independent logout quota"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second
                .admit_operator_auth_private(
                    Endpoint::Logout,
                    Private::AuthenticatedOperator(operator)
                )
                .await,
            Ok(Decision::RateLimited(_))
        ));
        for _ in 0..30 {
            assert_eq!(
                first
                    .admit_operator_auth_source(Endpoint::Logout, source())
                    .await
                    .expect("logout source quota"),
                Decision::Admitted
            );
        }
        assert!(matches!(
            second.admit_operator_auth_source(Endpoint::Logout, source()).await,
            Ok(Decision::RateLimited(_))
        ));
        assert!(matches!(
            first
                .admit_operator_auth_private(Endpoint::LoginOptions, Private::SetupDigest(&digest))
                .await,
            Err(OperatorAdmissionError::InvalidInput)
        ));
        assert!(matches!(
            first
                .admit_operator_auth_private(Endpoint::SetupFinish, Private::Ceremony(ceremony))
                .await,
            Err(OperatorAdmissionError::InvalidInput)
        ));
        let device_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_auth_admission")
            .fetch_one(first.pool())
            .await
            .expect("device admission untouched");
        assert_eq!(device_rows, 0);
    }};
}

macro_rules! cooldowns {
    ($store:expr,$fail_sql:expr,$clear_sql:expr) => {{
        let store=&$store;
        let endpoint=Endpoint::SetupFinish;
        let digest=[13;32];
        assert_eq!(store.admit_operator_auth_source(endpoint,source()).await.expect("source admitted"),Decision::Admitted);
        assert_eq!(store.admit_operator_auth_private(endpoint,Private::SetupDigest(&digest)).await.expect("digest admitted"),Decision::Admitted);
        store.audit_operator_auth_failure(endpoint,Reason::AuthenticationDenied,source(),Some(Private::SetupDigest(&digest))).await.expect("audited denial");
        let before:Vec<(i64,i64,i64,Option<i64>)>=sqlx::query_as("SELECT kind, attempts, failure_streak, cooldown_until_ms FROM operator_auth_admission ORDER BY kind").fetch_all(store.pool()).await.expect("before");
        assert_eq!(before.len(),2);
        assert!(before.iter().all(|r| r.1==1 && r.2==1 && r.3.is_some()));
        assert!(matches!(store.admit_operator_auth_source(endpoint,source()).await,Ok(Decision::RateLimited(1))));
        store.audit_operator_auth_failure(endpoint,Reason::RateLimited,source(),Some(Private::SetupDigest(&digest))).await.expect("429 audit");
        let after:Vec<(i64,i64,i64,Option<i64>)>=sqlx::query_as("SELECT kind, attempts, failure_streak, cooldown_until_ms FROM operator_auth_admission ORDER BY kind").fetch_all(store.pool()).await.expect("after");
        assert_eq!(before,after,"blocked requests do not increment or extend cooldown");
        sqlx::query("UPDATE operator_auth_admission SET cooldown_until_ms=0").execute(store.pool()).await.expect("fixture elapses cooldown");
        sqlx::raw_sql($fail_sql).execute(store.pool()).await.expect("failure injection");
        assert!(matches!(store.audit_operator_auth_failure(endpoint,Reason::AuthenticationDenied,source(),Some(Private::SetupDigest(&digest))).await,Err(OperatorAdmissionError::Audit)));
        let streaks:Vec<i64>=sqlx::query_scalar("SELECT failure_streak FROM operator_auth_admission").fetch_all(store.pool()).await.expect("rolled back streak");
        assert_eq!(streaks,vec![1,1]);
        sqlx::raw_sql($clear_sql).execute(store.pool()).await.expect("remove failure injection");
        store.audit_operator_auth_failure(endpoint,Reason::AuthenticationDenied,source(),Some(Private::SetupDigest(&digest))).await.expect("second denial");
        assert!(matches!(store.admit_operator_auth_private(endpoint,Private::SetupDigest(&digest)).await,Ok(Decision::RateLimited(2))));
        sqlx::query("UPDATE operator_auth_admission SET last_failure_ms=$1, cooldown_until_ms=0").bind(millis()-600_001).execute(store.pool()).await.expect("idle reset fixture");
        assert_eq!(store.admit_operator_auth_source(endpoint,source()).await.expect("idle resets streak"),Decision::Admitted);
        let events:Vec<Vec<u8>>=sqlx::query_scalar("SELECT event_bytes FROM deployment_audit_events").fetch_all(store.pool()).await.expect("audit events");
        assert_eq!(events.len(),3,"failed audit rolls back");
        for event in events { assert_eq!(event.len(),b"spl-operator-auth-failure-v1".len()+10,"audit contains codes and time only"); }
        store.verify_deployment_audit_chain().await.expect("valid audit chain");
    }};
}

macro_rules! replay {
    ($first:expr,$second:expr) => {{
        let first = &$first;
        let second = &$second;
        let mut scalar = [0; 32];
        scalar[31] = 1;
        let key = P256SigningKey::from_bytes(&scalar).expect("key");
        let jkt = dpop_jwk_thumbprint(&key.public_key_sec1()).expect("JKT");
        let target =
            DpopTarget::new("POST", "https://setup.example.com", "/api/v1/auth/login/options")
                .expect("target");
        let proof = DpopProof::sign(
            &key,
            &key.public_key_sec1(),
            &target,
            DpopToken::Refresh,
            u64::try_from(millis() / 1000).expect("time"),
            None,
        )
        .expect("proof");
        let wrong =
            base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, [19; 32]);
        assert!(matches!(
            first.claim_operator_dpop_proof(&proof, &target, DpopToken::Refresh, &wrong).await,
            Err(OperatorAdmissionError::InvalidDpopProof)
        ));
        let (a, b) = tokio::join!(
            first.claim_operator_dpop_proof(&proof, &target, DpopToken::Refresh, &jkt),
            second.claim_operator_dpop_proof(&proof, &target, DpopToken::Refresh, &jkt)
        );
        assert!(matches!(
            (a, b),
            (Ok(()), Err(OperatorAdmissionError::InvalidDpopProof))
                | (Err(OperatorAdmissionError::InvalidDpopProof), Ok(()))
        ));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM operator_dpop_replays")
            .fetch_one(first.pool())
            .await
            .expect("one replay row");
        assert_eq!(rows, 1);
        let row = sqlx::query("SELECT jti_digest, retain_until_ms FROM operator_dpop_replays")
            .fetch_one(first.pool())
            .await
            .expect("digest only");
        assert_eq!(row.get::<Vec<u8>, _>("jti_digest").len(), 32);
        assert!(row.get::<i64, _>("retain_until_ms") > millis());
        let wrong_target =
            DpopTarget::new("POST", "https://setup.example.com", "/api/v1/auth/login/finish")
                .expect("different route");
        assert!(matches!(
            first.claim_operator_dpop_proof(&proof, &wrong_target, DpopToken::Refresh, &jkt).await,
            Err(OperatorAdmissionError::InvalidDpopProof)
        ));
        let expired = DpopProof::sign(
            &key,
            &key.public_key_sec1(),
            &target,
            DpopToken::Refresh,
            u64::try_from(millis() / 1000 - 301).expect("time"),
            None,
        )
        .expect("old proof");
        assert!(matches!(
            first.claim_operator_dpop_proof(&expired, &target, DpopToken::Refresh, &jkt).await,
            Err(OperatorAdmissionError::InvalidDpopProof)
        ));
        let device_rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM device_dpop_replays")
            .fetch_one(first.pool())
            .await
            .expect("device proofs untouched");
        assert_eq!(device_rows, 0);
    }};
}

#[tokio::test]
async fn sqlite_durable_quotas_across_replicas() {
    let (store, dir) = sqlite().await;
    let replica = SqliteStore::open(&dir.join("store.sqlite")).await.expect("second pool");
    quotas!(store, replica);
    store.pool().close().await;
    replica.pool().close().await;
    support::remove_test_directory(dir).await;
}
#[tokio::test]
async fn sqlite_denial_cooldown_is_atomic_with_audit() {
    let (store, dir) = sqlite().await;
    cooldowns!(
        store,
        "CREATE TRIGGER deny_operator_admission_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'fixture failure'); END",
        "DROP TRIGGER deny_operator_admission_audit"
    );
    store.pool().close().await;
    support::remove_test_directory(dir).await;
}
#[tokio::test]
async fn sqlite_proof_verification_and_durable_replay() {
    let (store, dir) = sqlite().await;
    let replica = SqliteStore::open(&dir.join("store.sqlite")).await.expect("second pool");
    replay!(store, replica);
    store.pool().close().await;
    replica.pool().close().await;
    support::remove_test_directory(dir).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (scoplen_store::PostgresStore, sqlx::PgPool, String, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PG fixture");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture admin pool");
    let schema = format!("operator_admission_{}", uuid::Uuid::new_v4().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("PG URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let database = url.to_string();
    let store = scoplen_store::PostgresStore::connect(&database).await.expect("PG store");
    (store, pool, schema, database)
}
#[cfg(feature = "postgres-integration")]
async fn cleanup(store: scoplen_store::PostgresStore, pool: sqlx::PgPool, schema: String) {
    store.pool().close().await;
    assert!(
        schema.starts_with("operator_admission_")
            && schema.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'_')
    );
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_quotas_cooldown_audit_and_replay() {
    let (store, pool, schema, database) = postgres_fixture().await;
    let replica = scoplen_store::PostgresStore::connect(&database).await.expect("second pool");
    quotas!(store, replica);
    sqlx::query("DELETE FROM operator_auth_admission")
        .execute(store.pool())
        .await
        .expect("reset owned admission fixture");
    cooldowns!(
        store,
        "CREATE FUNCTION deny_operator_admission_audit() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'fixture failure'; END; $$; CREATE TRIGGER deny_operator_admission_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION deny_operator_admission_audit()",
        "DROP TRIGGER deny_operator_admission_audit ON deployment_audit_events; DROP FUNCTION deny_operator_admission_audit()"
    );
    replay!(store, replica);
    replica.pool().close().await;
    cleanup(store, pool, schema).await;
}
