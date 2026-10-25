// SPDX-License-Identifier: AGPL-3.0-only

#[cfg(feature = "postgres-integration")]
#[path = "support/lost_commit.rs"]
mod lost_commit;
mod support;

use scoplen_store::{
    RelationalStore, SqliteStore, account_probe_key::AccountProbeKeyError,
    kms::KeyManagementService,
};

struct TestKms([u8; 32]);

impl KeyManagementService for TestKms {
    fn key_encryption_key(&self) -> &[u8; 32] {
        &self.0
    }

    fn backend_name(&self) -> &'static str {
        "test"
    }
}

fn sql(source: &str, postgres: bool) -> String {
    if !postgres {
        return source.to_owned();
    }
    let mut parameter = 0;
    source
        .chars()
        .map(|character| {
            if character == '?' {
                parameter += 1;
                format!("${parameter}")
            } else {
                character.to_string()
            }
        })
        .collect()
}

macro_rules! lifecycle {
    ($store:expr, $second:expr, $postgres:literal) => {{
        let store = &$store;
        let second = &$second;
        let mut tasks = Vec::new();
        for index in 0..8 {
            let instance = if index % 2 == 0 { store.clone() } else { second.clone() };
            tasks.push(tokio::spawn(async move {
                instance.ensure_account_probe_key(&TestKms([7; 32])).await.expect("probe key")
            }));
        }
        let mut keys = Vec::new();
        for task in tasks {
            keys.push(task.await.expect("initialization task"));
        }
        let original = &keys[0];
        assert!(keys.iter().all(|key| key.as_bytes() == original.as_bytes()));
        assert_eq!(format!("{original:?}"), "AccountProbeKey([REDACTED])");
        assert!(original.as_bytes() != &[0; 32]);
        assert!(original.as_bytes() != &[7; 32]);
        let stored: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_key FROM account_password_probe_key")
                .fetch_one(store.pool())
                .await
                .expect("encrypted key");
        assert_eq!(stored.len(), 73);
        assert_eq!(stored[0], 1);
        assert!(!stored.windows(32).any(|bytes| bytes == original.as_bytes()));
        assert_eq!(
            store
                .deployment_audit_head()
                .await
                .expect("audit head")
                .expect("creation event")
                .sequence,
            1
        );
        for invalid in [[0; 32], [8; 32]] {
            assert!(matches!(
                store.ensure_account_probe_key(&TestKms(invalid)).await,
                Err(AccountProbeKeyError::Integrity)
            ));
            assert!(matches!(
                store.rewrap_account_probe_key(&TestKms(invalid), &TestKms([9; 32])).await,
                Err(AccountProbeKeyError::Integrity)
            ));
        }
        assert!(matches!(
            store.rewrap_account_probe_key(&TestKms([7; 32]), &TestKms([0; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        store
            .rewrap_account_probe_key(&TestKms([7; 32]), &TestKms([9; 32]))
            .await
            .expect("rewrap same probe key");
        let rewrapped = second
            .ensure_account_probe_key(&TestKms([9; 32]))
            .await
            .expect("independent instance observes rewrap");
        assert!(rewrapped.as_bytes() == original.as_bytes());
        assert!(matches!(
            store.ensure_account_probe_key(&TestKms([7; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        let ciphertext: Vec<u8> =
            sqlx::query_scalar("SELECT encrypted_key FROM account_password_probe_key")
                .fetch_one(store.pool())
                .await
                .expect("rewrapped ciphertext");
        assert!(stored != ciphertext);
        assert_eq!(
            store
                .deployment_audit_head()
                .await
                .expect("audit head")
                .expect("rewrap event")
                .sequence,
            2
        );

        let created: i64 =
            sqlx::query_scalar("SELECT created_at_ms FROM account_password_probe_key")
                .fetch_one(store.pool())
                .await
                .expect("creation metadata");
        assert!(
            sqlx::query(&sql("UPDATE account_password_probe_key SET created_at_ms=?", $postgres))
                .bind(created + 1)
                .execute(store.pool())
                .await
                .is_err()
        );
        for reset in [
            "UPDATE account_password_probe_key SET encrypted_key=NULL, created_at_ms=NULL",
            "DELETE FROM account_password_probe_key",
        ] {
            assert!(sqlx::query(reset).execute(store.pool()).await.is_err());
        }
        let replace = if $postgres {
            "INSERT INTO account_password_probe_key (singleton) VALUES (1) ON CONFLICT (singleton) DO UPDATE SET encrypted_key=NULL, created_at_ms=NULL"
        } else {
            "INSERT OR REPLACE INTO account_password_probe_key (singleton) VALUES (1)"
        };
        assert!(sqlx::query(replace).execute(store.pool()).await.is_err());
        if $postgres {
            assert!(
                sqlx::query("TRUNCATE account_password_probe_key")
                    .execute(store.pool())
                    .await
                    .is_err()
            );
        }
        assert!(
            second
                .ensure_account_probe_key(&TestKms([9; 32]))
                .await
                .expect("reset attempts preserve the original key")
                .as_bytes()
                == original.as_bytes()
        );
        assert_eq!(store.deployment_audit_head().await.expect("audit").expect("head").sequence, 2);
        let mut tampered = ciphertext.clone();
        tampered[40] ^= 1;
        sqlx::query(&sql("UPDATE account_password_probe_key SET encrypted_key=?", $postgres))
            .bind(&tampered)
            .execute(store.pool())
            .await
            .expect("tamper ciphertext");
        assert!(matches!(
            store.ensure_account_probe_key(&TestKms([9; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        sqlx::query(&sql("UPDATE account_password_probe_key SET encrypted_key=?", $postgres))
            .bind(&ciphertext)
            .execute(store.pool())
            .await
            .expect("restore ciphertext");

        store.ensure_device_token_keyring(&TestKms([9; 32])).await.expect("independent token key");
        sqlx::query("UPDATE device_access_token_keys SET activated_at_ms=1 WHERE active_slot=1")
            .execute(store.pool())
            .await
            .expect("age token key");
        let token_ring = store
            .ensure_device_token_keyring(&TestKms([9; 32]))
            .await
            .expect("rotate token key independently");
        assert_eq!(token_ring.verification_keys().len(), 2);
        assert!(
            store
                .ensure_account_probe_key(&TestKms([9; 32]))
                .await
                .expect("token rotation preserves probe")
                .as_bytes()
                == original.as_bytes()
        );
        let token_envelope: Vec<u8> = sqlx::query_scalar(
            "SELECT encrypted_seed FROM device_access_token_keys WHERE active_slot=1",
        )
        .fetch_one(store.pool())
        .await
        .expect("token envelope");
        sqlx::query(&sql("UPDATE account_password_probe_key SET encrypted_key=?", $postgres))
            .bind(token_envelope)
            .execute(store.pool())
            .await
            .expect("cross-purpose envelope");
        assert!(matches!(
            store.ensure_account_probe_key(&TestKms([9; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        sqlx::query(&sql("UPDATE account_password_probe_key SET encrypted_key=?", $postgres))
            .bind(ciphertext)
            .execute(store.pool())
            .await
            .expect("restore probe envelope");
        assert!(
            store
                .ensure_account_probe_key(&TestKms([9; 32]))
                .await
                .expect("restored key")
                .as_bytes()
                == original.as_bytes()
        );
    }};
}

macro_rules! constraints {
    ($store:expr, $postgres:literal) => {{
        let store = &$store;
        assert!(matches!(
            store.ensure_account_probe_key(&TestKms([0; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        assert!(store.deployment_audit_head().await.expect("no audit").is_none());
        assert!(
            sqlx::query("INSERT INTO account_password_probe_key (singleton) VALUES (2)")
                .execute(store.pool())
                .await
                .is_err()
        );
        for (key, time) in [
            (None::<Vec<u8>>, Some(1_i64)),
            (Some(vec![0; 73]), None),
            (Some(vec![0; 72]), Some(1)),
            (Some(vec![0; 73]), Some(0)),
        ] {
            assert!(
                sqlx::query(&sql(
                    "UPDATE account_password_probe_key SET encrypted_key=?, created_at_ms=?",
                    $postgres
                ))
                .bind(key)
                .bind(time)
                .execute(store.pool())
                .await
                .is_err()
            );
        }
        sqlx::query("DELETE FROM account_password_probe_key")
            .execute(store.pool())
            .await
            .expect("simulate missing singleton");
        assert!(matches!(
            store.ensure_account_probe_key(&TestKms([7; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM account_password_probe_key")
            .fetch_one(store.pool())
            .await
            .expect("missing row remains missing");
        assert_eq!(rows, 0);
    }};
}

macro_rules! audit_rollback {
    ($store:expr, $create:literal, $remove:literal) => {{
        let store = &$store;
        sqlx::raw_sql($create).execute(store.pool()).await.expect("install audit failure");
        assert!(matches!(
            store.ensure_account_probe_key(&TestKms([7; 32])).await,
            Err(AccountProbeKeyError::Audit(_))
        ));
        let key: Option<Vec<u8>> =
            sqlx::query_scalar("SELECT encrypted_key FROM account_password_probe_key")
                .fetch_one(store.pool())
                .await
                .expect("uninitialized singleton");
        assert!(key.is_none());
        assert!(store.deployment_audit_head().await.expect("rolled-back audit").is_none());
        sqlx::raw_sql($remove).execute(store.pool()).await.expect("remove audit failure");
        let original = store
            .ensure_account_probe_key(&TestKms([7; 32]))
            .await
            .expect("initialize after rollback");
        sqlx::raw_sql($create).execute(store.pool()).await.expect("install rewrap failure");
        assert!(matches!(
            store.rewrap_account_probe_key(&TestKms([7; 32]), &TestKms([9; 32])).await,
            Err(AccountProbeKeyError::Audit(_))
        ));
        assert!(
            store
                .ensure_account_probe_key(&TestKms([7; 32]))
                .await
                .expect("old protection remains")
                .as_bytes()
                == original.as_bytes()
        );
        assert!(matches!(
            store.ensure_account_probe_key(&TestKms([9; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        assert_eq!(
            store
                .deployment_audit_head()
                .await
                .expect("audit head")
                .expect("initialization only")
                .sequence,
            1
        );
        sqlx::raw_sql($remove).execute(store.pool()).await.expect("remove rewrap failure");
    }};
}

macro_rules! ignored_write {
    ($store:expr, $create:literal, $remove:literal) => {{
        let store = &$store;
        sqlx::raw_sql($create).execute(store.pool()).await.expect("suppress key write");
        assert!(matches!(
            store.ensure_account_probe_key(&TestKms([7; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        assert!(store.deployment_audit_head().await.expect("no creation audit").is_none());
        sqlx::raw_sql($remove).execute(store.pool()).await.expect("restore writes");
        let original = store.ensure_account_probe_key(&TestKms([7; 32])).await.expect("initialize");
        sqlx::raw_sql($create).execute(store.pool()).await.expect("suppress rewrap write");
        assert!(matches!(
            store.rewrap_account_probe_key(&TestKms([7; 32]), &TestKms([9; 32])).await,
            Err(AccountProbeKeyError::Integrity)
        ));
        assert!(
            store
                .ensure_account_probe_key(&TestKms([7; 32]))
                .await
                .expect("original protection")
                .as_bytes()
                == original.as_bytes()
        );
        assert_eq!(
            store
                .deployment_audit_head()
                .await
                .expect("audit head")
                .expect("initialization only")
                .sequence,
            1
        );
        sqlx::raw_sql($remove).execute(store.pool()).await.expect("restore rewrap writes");
    }};
}

#[tokio::test]
async fn sqlite_probe_key_serializes_pools_rewraps_and_survives_restart() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-account-probe-{}", uuid::Uuid::now_v7()));
    let path = directory.join("store.sqlite");
    let store = SqliteStore::open(&path).await.expect("store");
    let second = SqliteStore::open(&path).await.expect("independent pool");
    lifecycle!(store, second, false);
    let original = store.ensure_account_probe_key(&TestKms([9; 32])).await.expect("before restart");
    second.pool().close().await;
    store.pool().close().await;
    let reopened = SqliteStore::open(&path).await.expect("reopen");
    let restored =
        reopened.ensure_account_probe_key(&TestKms([9; 32])).await.expect("after restart");
    let unchanged = restored.as_bytes() == original.as_bytes();
    assert!(unchanged, "restart preserves probe key");
    reopened.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_probe_key_constraints_and_missing_row_fail_closed() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-account-probe-{}", uuid::Uuid::now_v7()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    constraints!(store, false);
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_probe_key_initialization_and_rewrap_are_audit_atomic() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-account-probe-{}", uuid::Uuid::now_v7()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    audit_rollback!(
        store,
        "CREATE TRIGGER fail_probe_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT,'audit unavailable'); END",
        "DROP TRIGGER fail_probe_audit"
    );
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_probe_key_does_not_disclose_unpersisted_or_unrewrapped_keys() {
    let directory =
        std::env::temp_dir().join(format!("scoplen-account-probe-{}", uuid::Uuid::now_v7()));
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    ignored_write!(
        store,
        "CREATE TRIGGER ignore_probe_write BEFORE UPDATE ON account_password_probe_key BEGIN SELECT RAISE(IGNORE); END",
        "DROP TRIGGER ignore_probe_write"
    );
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (String, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("account_probe_{}", uuid::Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
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
async fn postgres_probe_key_truncate_guard_uses_the_target_schema() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    let original = store.ensure_account_probe_key(&TestKms([7; 32])).await.expect("probe key");
    let mut other = pool.acquire().await.expect("separate schema connection");
    sqlx::query("CREATE TEMP TABLE account_password_probe_key (encrypted_key BYTEA)")
        .execute(&mut *other)
        .await
        .expect("same-name caller table");
    sqlx::query("INSERT INTO account_password_probe_key (encrypted_key) VALUES (NULL)")
        .execute(&mut *other)
        .await
        .expect("uninitialized caller state");
    let rejected = sqlx::query(&format!("TRUNCATE {schema}.account_password_probe_key"))
        .execute(&mut *other)
        .await
        .is_err();
    drop(other);
    let retained = store
        .ensure_account_probe_key(&TestKms([7; 32]))
        .await
        .is_ok_and(|key| key.as_bytes() == original.as_bytes());
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
    assert!(rejected, "caller search_path cannot permit target key removal");
    assert!(retained, "target probe key remains unchanged");
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_probe_key_serializes_pools_rewraps_and_survives_restart() {
    use scoplen_store::PostgresStore;
    let (url, pool, schema) = postgres_fixture().await;
    let store = PostgresStore::connect(&url).await.expect("store");
    let second = PostgresStore::connect(&url).await.expect("independent pool");
    lifecycle!(store, second, true);
    let original = store.ensure_account_probe_key(&TestKms([9; 32])).await.expect("before restart");
    second.pool().close().await;
    store.pool().close().await;
    let reopened = PostgresStore::connect(&url).await.expect("reopen");
    let restored =
        reopened.ensure_account_probe_key(&TestKms([9; 32])).await.expect("after restart");
    let unchanged = restored.as_bytes() == original.as_bytes();
    assert!(unchanged, "restart preserves probe key");
    reopened.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_probe_key_constraints_and_missing_row_fail_closed() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    constraints!(store, true);
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_probe_key_initialization_and_rewrap_are_audit_atomic() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    audit_rollback!(
        store,
        "CREATE FUNCTION fail_probe_audit() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RAISE EXCEPTION ''audit unavailable''; END'; CREATE TRIGGER fail_probe_audit BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION fail_probe_audit()",
        "DROP TRIGGER fail_probe_audit ON deployment_audit_events; DROP FUNCTION fail_probe_audit()"
    );
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_probe_key_does_not_disclose_unpersisted_or_unrewrapped_keys() {
    let (url, pool, schema) = postgres_fixture().await;
    let store = scoplen_store::PostgresStore::connect(&url).await.expect("store");
    ignored_write!(
        store,
        "CREATE FUNCTION ignore_probe_write() RETURNS trigger LANGUAGE plpgsql AS 'BEGIN RETURN NULL; END'; CREATE TRIGGER ignore_probe_write BEFORE UPDATE ON account_password_probe_key FOR EACH ROW EXECUTE FUNCTION ignore_probe_write()",
        "DROP TRIGGER ignore_probe_write ON account_password_probe_key; DROP FUNCTION ignore_probe_write()"
    );
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_probe_key_discloses_nothing_after_unconfirmed_commit() {
    use scoplen_store::PostgresStore;
    use std::sync::atomic::Ordering;
    let (url, pool, schema) = postgres_fixture().await;
    let store = PostgresStore::connect(&url).await.expect("store");
    let proxy = lost_commit::LostCommitProxy::start(&url).await;
    let uncertain = PostgresStore::connect(&proxy.database_url).await.expect("proxied store");
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain.ensure_account_probe_key(&TestKms([7; 32])).await,
        Err(AccountProbeKeyError::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let original =
        store.ensure_account_probe_key(&TestKms([7; 32])).await.expect("load committed original");
    assert_eq!(
        store
            .deployment_audit_head()
            .await
            .expect("audit head")
            .expect("one initialization")
            .sequence,
        1
    );
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain.ensure_account_probe_key(&TestKms([7; 32])).await,
        Err(AccountProbeKeyError::Storage(_))
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 2);
    proxy.armed.store(true, Ordering::SeqCst);
    assert!(matches!(
        uncertain.rewrap_account_probe_key(&TestKms([7; 32]), &TestKms([9; 32])).await,
        Err(AccountProbeKeyError::CommitOutcomeUnknown)
    ));
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 3);
    let rewrapped = store
        .ensure_account_probe_key(&TestKms([9; 32]))
        .await
        .expect("rewrapped committed original");
    let unchanged = rewrapped.as_bytes() == original.as_bytes();
    assert!(unchanged, "rewrap preserves committed probe key");
    assert!(matches!(
        store.ensure_account_probe_key(&TestKms([7; 32])).await,
        Err(AccountProbeKeyError::Integrity)
    ));
    assert_eq!(
        store.deployment_audit_head().await.expect("audit head").expect("one rewrap").sequence,
        2
    );
    uncertain.pool().close().await;
    store.pool().close().await;
    cleanup_postgres(pool, schema).await;
}
