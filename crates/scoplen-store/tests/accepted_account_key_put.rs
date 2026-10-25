// SPDX-License-Identifier: AGPL-3.0-only

#[path = "support/legacy_identity.rs"]
mod legacy_identity;
mod support;
#[cfg(feature = "postgres-integration")]
use legacy_identity::seed_postgres;
use legacy_identity::{LegacyIdentity, seed_sqlite};
use scoplen_api::sync::SyncAccountDeviceWrap;
use scoplen_crypto::{Ed25519SigningKey, P256SigningKey};
use scoplen_store::{
    RelationalStore, SqliteStore,
    account_keys::{AccountKeyBundlePut, AccountKeyBundleUpdate, AccountKeyStoreError},
};
use std::path::PathBuf;
#[cfg(feature = "postgres-integration")]
use std::time::Duration;
use support::remove_test_directory;
use uuid::Uuid;

#[path = "support/pool_close.rs"]
mod pool_close;

fn account_key() -> Ed25519SigningKey {
    Ed25519SigningKey::from_bytes(&[1; 32]).expect("Account signing key")
}
fn fixture() -> LegacyIdentity {
    let mut scalar = [0; 32];
    scalar[31] = 1;
    LegacyIdentity::new(&account_key(), &P256SigningKey::from_bytes(&scalar).expect("Device key"))
}
fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-accepted-put-{}", Uuid::new_v4()));
    std::fs::create_dir(&path).expect("owned test directory");
    path
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

macro_rules! contract {
    ($store:expr, $postgres:literal, $seed:ident) => {{
        let store = &$store;
        let request = fixture();
        $seed(store.pool(), &request, true).await;
        let account = request.account_id.into_bytes();
        let first = request.key_bundle_update.to_cbor().expect("exact first PUT");
        assert_eq!(
            store.read_accepted_account_key_put(account).await.expect("first evidence"),
            Some(first.clone())
        );
        let raw = AccountKeyBundleUpdate::try_from(&request.key_bundle_update).expect("projection");
        assert!(matches!(
            store.put_account_key_bundle(account, &raw).await,
            Ok(AccountKeyBundlePut::Replay { revision: 1 })
        ));
        assert_eq!(
            store.read_accepted_account_key_put(account).await.expect("replay retains evidence"),
            Some(first)
        );

        let principal = store
            .current_device_principal(request.device_certificate.device_id.into_bytes())
            .await
            .expect("principal")
            .expect("current device");
        let expiry = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_secs()
            + scoplen_api::auth::ACCESS_TOKEN_EXPIRES_IN;
        let mut candidate = request.key_bundle_update.clone();
        candidate.revision = 2;
        candidate.device_wraps[0].wrapped_ark = vec![40];
        candidate.signature =
            account_key().sign(&candidate.signature_input().expect("signature input")).to_vec();
        store
            .publish_account_key_bundle(&principal, expiry, &candidate)
            .await
            .expect("verified publication");
        let second = candidate.to_cbor().expect("second PUT");
        assert_eq!(
            store.read_accepted_account_key_put(account).await.expect("new evidence"),
            Some(second.clone())
        );

        let mut next = candidate.clone();
        next.revision = 3;
        next.signature =
            account_key().sign(&next.signature_input().expect("signature input")).to_vec();
        let raw = AccountKeyBundleUpdate::try_from(&next).expect("raw next projection");
        store.put_account_key_bundle(account, &raw).await.expect("lower-level new revision");
        assert!(
            store
                .read_accepted_account_key_put(account)
                .await
                .expect("invalidated evidence")
                .is_none()
        );
        store.put_account_key_bundle(account, &raw).await.expect("lower-level exact replay");
        store
            .publish_account_key_bundle(&principal, expiry, &next)
            .await
            .expect("production exact replay");
        assert!(
            store
                .read_accepted_account_key_put(account)
                .await
                .expect("no historical backfill")
                .is_none()
        );

        next.revision = 4;
        next.signature =
            account_key().sign(&next.signature_input().expect("signature input")).to_vec();
        store
            .publish_account_key_bundle(&principal, expiry, &next)
            .await
            .expect("new verified evidence");
        let mut rival = next.clone();
        rival.revision = 5;
        rival.signature =
            account_key().sign(&rival.signature_input().expect("signature input")).to_vec();
        let mut alternative = rival.clone();
        alternative.device_wraps[0].wrapped_ark = vec![41];
        alternative.signature =
            account_key().sign(&alternative.signature_input().expect("signature input")).to_vec();
        let (left, right) = tokio::join!(
            store.publish_account_key_bundle(&principal, expiry, &rival),
            store.publish_account_key_bundle(&principal, expiry, &alternative),
        );
        assert_eq!(usize::from(left.is_ok()) + usize::from(right.is_ok()), 1);
        let winner = if left.is_ok() { &rival } else { &alternative };
        assert_eq!(
            store.read_accepted_account_key_put(account).await.expect("winning CAS evidence"),
            Some(winner.to_cbor().expect("winner PUT"))
        );

        sqlx::query(&sql(
            "UPDATE sync_account_key_bundles SET accepted_put_cbor = NULL WHERE account_id = ?",
            $postgres,
        ))
        .bind(account.as_slice())
        .execute(store.pool())
        .await
        .expect("legacy projection without evidence");
        store
            .publish_account_key_bundle(&principal, expiry, winner)
            .await
            .expect("legacy exact replay");
        assert!(
            store
                .read_accepted_account_key_put(account)
                .await
                .expect("legacy remains unsupported")
                .is_none()
        );
        assert!(matches!(
            store.read_accepted_account_key_put(Uuid::now_v7().into_bytes()).await,
            Err(AccountKeyStoreError::BundleNotFound)
        ));
    }};
}

macro_rules! corruption {
    ($store:expr, $postgres:literal, $seed:ident) => {{
        let store = &$store;
        let request = fixture();
        $seed(store.pool(), &request, true).await;
        let account = request.account_id.into_bytes();
        let original_bytes = request.key_bundle_update.to_cbor().expect("exact evidence");
        let original = original_bytes.as_slice();
        let revision = sql("UPDATE sync_account_key_bundles SET revision = ? WHERE account_id = ?", $postgres);
        sqlx::query(&revision).bind(2_i64).bind(account.as_slice()).execute(store.pool()).await.expect("damage revision");
        assert!(matches!(store.read_accepted_account_key_put(account).await, Err(AccountKeyStoreError::CorruptRow(_))));
        sqlx::query(&revision).bind(1_i64).bind(account.as_slice()).execute(store.pool()).await.expect("restore revision");
        for (field, original) in [
            ("account_signing_key", request.key_bundle_update.account_signing_key.clone()), ("account_kem_key", request.key_bundle_update.account_kem_key.clone()),
            ("recovery_blob", request.key_bundle_update.recovery_blob.clone()), ("signature", request.key_bundle_update.signature.clone()),
        ] {
            let query = sql(&format!("UPDATE sync_account_key_bundles SET {field} = ? WHERE account_id = ?"), $postgres);
            sqlx::query(&query).bind(vec![99_u8; original.len()]).bind(account.as_slice()).execute(store.pool()).await.expect("damage projected field");
            assert!(matches!(store.read_accepted_account_key_put(account).await, Err(AccountKeyStoreError::CorruptRow(_))), "{field}");
            sqlx::query(&query).bind(original).bind(account.as_slice()).execute(store.pool()).await.expect("restore projected field");
        }
        let wrap_query = sql("UPDATE sync_account_key_device_wraps SET wrapped_ark = ? WHERE account_id = ?", $postgres);
        sqlx::query(&wrap_query).bind(vec![66_u8]).bind(account.as_slice()).execute(store.pool()).await.expect("damage wrap");
        assert!(matches!(store.read_accepted_account_key_put(account).await, Err(AccountKeyStoreError::CorruptRow(_))));
        sqlx::query(&wrap_query).bind(&request.key_bundle_update.device_wraps[0].wrapped_ark).bind(account.as_slice()).execute(store.pool()).await.expect("restore wrap");
        let insert = sql("INSERT INTO sync_account_key_device_wraps (account_id, device_id, wrapped_ark) VALUES (?, ?, ?)", $postgres);
        let extra = Uuid::now_v7();
        let recipient = sql("UPDATE sync_account_key_device_wraps SET device_id = ? WHERE account_id = ?", $postgres);
        sqlx::query(&recipient).bind(extra.as_bytes().as_slice()).bind(account.as_slice()).execute(store.pool()).await.expect("substitute recipient");
        assert!(matches!(store.read_accepted_account_key_put(account).await, Err(AccountKeyStoreError::CorruptRow(_))));
        sqlx::query(&recipient).bind(request.device_certificate.device_id.into_bytes().as_slice()).bind(account.as_slice()).execute(store.pool()).await.expect("restore recipient");
        sqlx::query(&insert).bind(account.as_slice()).bind(extra.as_bytes().as_slice()).bind(vec![5_u8]).execute(store.pool()).await.expect("extra wrap");
        assert!(matches!(store.read_accepted_account_key_put(account).await, Err(AccountKeyStoreError::CorruptRow(_))));
        let delete = sql("DELETE FROM sync_account_key_device_wraps WHERE account_id = ?", $postgres);
        sqlx::query(&delete).bind(account.as_slice()).execute(store.pool()).await.expect("missing wraps");
        assert!(matches!(store.read_accepted_account_key_put(account).await, Err(AccountKeyStoreError::CorruptRow(_))));
        sqlx::query(&insert).bind(account.as_slice()).bind(request.device_certificate.device_id.as_bytes().as_slice()).bind(&request.key_bundle_update.device_wraps[0].wrapped_ark).execute(store.pool()).await.expect("restore recipient");
        let evidence = sql("UPDATE sync_account_key_bundles SET accepted_put_cbor = ? WHERE account_id = ?", $postgres);
        for invalid in [vec![0; original.len()], [original, &[0]].concat()] {
            sqlx::query(&evidence).bind(invalid).bind(account.as_slice()).execute(store.pool()).await.expect("damage evidence");
            assert!(matches!(store.read_accepted_account_key_put(account).await, Err(AccountKeyStoreError::CorruptRow(_))));
        }
        for oversized in [Vec::<u8>::new(), vec![0_u8; 4_194_305]] {
            assert!(sqlx::query(&evidence).bind(oversized).bind(account.as_slice()).execute(store.pool()).await.is_err());
        }
        sqlx::query(&evidence).bind(original).bind(account.as_slice()).execute(store.pool()).await.expect("restore exact evidence");
        assert_eq!(store.read_accepted_account_key_put(account).await.expect("complete restored evidence"), Some(original.to_vec()));

        // Exercise the reader's maximum set independently of bootstrap certificate validation.
        let mut maximum = request.key_bundle_update.clone();
        maximum.revision = 2;
        maximum.device_wraps = (0..1_000).map(|_| SyncAccountDeviceWrap {
            device_id: Uuid::now_v7(), wrapped_ark: vec![5],
        }).collect();
        maximum.device_wraps.sort_by_key(|wrap| wrap.device_id);
        maximum.signature = account_key().sign(&maximum.signature_input().expect("maximum signature input")).to_vec();
        store.put_account_key_bundle(account, &AccountKeyBundleUpdate::try_from(&maximum).expect("maximum projection"))
            .await.expect("bounded reader fixture projection");
        let maximum_bytes = maximum.to_cbor().expect("maximum canonical PUT");
        sqlx::query(&evidence).bind(&maximum_bytes).bind(account.as_slice()).execute(store.pool()).await.expect("reader fixture evidence");
        assert_eq!(store.read_accepted_account_key_put(account).await.expect("all thousand wraps"), Some(maximum_bytes));
        sqlx::query(&insert).bind(account.as_slice()).bind(extra.as_bytes().as_slice()).bind(vec![5_u8]).execute(store.pool()).await.expect("over-count fixture");
        assert!(matches!(store.read_accepted_account_key_put(account).await, Err(AccountKeyStoreError::CorruptRow(_))));
    }};
}

#[tokio::test]
async fn sqlite_accepted_put_lifecycle_and_cas() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    contract!(store, false, seed_sqlite);
    pool_close::close(store.pool()).await;
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_accepted_put_rejects_damaged_evidence_and_projection() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    corruption!(store, false, seed_sqlite);
    pool_close::close(store.pool()).await;
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_upgrade_preserves_projection_without_fabricating_acceptance() {
    let directory = test_directory();
    let path = directory.join("store.sqlite");
    let pool = sqlx::sqlite::SqlitePoolOptions::new()
        .connect_with(
            sqlx::sqlite::SqliteConnectOptions::new().filename(&path).create_if_missing(true),
        )
        .await
        .expect("old database");
    let mut migrations = sqlx::migrate!("./migrations/sqlite");
    let current_migration_count =
        i64::try_from(migrations.migrations.len()).expect("migration count");
    migrations.migrations.to_mut().retain(|migration| migration.version < 20_261_025_030_000);
    migrations.run(&pool).await.expect("previous schema");
    let request = fixture();
    let account = request.account_id.into_bytes();
    let update = &request.key_bundle_update;
    sqlx::query("INSERT INTO sync_account_key_bundles (account_id, revision, account_signing_key, account_kem_key, recovery_blob, signature, updated_at_ms) VALUES (?, 1, ?, ?, ?, ?, 1)")
        .bind(account.as_slice()).bind(&update.account_signing_key).bind(&update.account_kem_key)
        .bind(&update.recovery_blob).bind(&update.signature).execute(&pool).await.expect("old bundle");
    sqlx::query("INSERT INTO sync_account_key_device_wraps (account_id, device_id, wrapped_ark) VALUES (?, ?, ?)")
        .bind(account.as_slice()).bind(update.device_wraps[0].device_id.as_bytes().as_slice())
        .bind(&update.device_wraps[0].wrapped_ark).execute(&pool).await.expect("old wrap");
    pool_close::close(&pool).await;
    let store = SqliteStore::open(&path).await.expect("forward upgrade");
    assert!(
        store
            .read_accepted_account_key_put(account)
            .await
            .expect("old evidence unavailable")
            .is_none()
    );
    let raw = AccountKeyBundleUpdate::try_from(update).expect("raw projection");
    assert!(matches!(
        store.put_account_key_bundle(account, &raw).await,
        Ok(AccountKeyBundlePut::Replay { revision: 1 })
    ));
    assert!(
        store
            .read_accepted_account_key_put(account)
            .await
            .expect("replay does not backfill")
            .is_none()
    );
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM _sqlx_migrations")
        .fetch_one(store.pool())
        .await
        .expect("migration history");
    assert_eq!(count, current_migration_count);
    assert_eq!(
        store
            .get_account_key_bundle(account, update.device_wraps[0].device_id.into_bytes())
            .await
            .expect("legacy serving projection")
            .wrapped_ark,
        update.device_wraps[0].wrapped_ark
    );
    pool_close::close(store.pool()).await;
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_accepted_put_rejects_oversized_metadata_before_loading_payloads() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("store.sqlite")).await.expect("store");
    let request = fixture();
    seed_sqlite(store.pool(), &request, true).await;
    let mut damaged = store.pool().acquire().await.expect("owned corruption connection");
    sqlx::query("PRAGMA ignore_check_constraints = ON")
        .execute(&mut *damaged)
        .await
        .expect("allow owned corruption");
    sqlx::query("UPDATE sync_account_key_bundles SET account_signing_key = zeroblob(65537) WHERE account_id = ?")
        .bind(request.account_id.into_bytes().as_slice()).execute(&mut *damaged).await.expect("oversized projection");
    sqlx::query("PRAGMA ignore_check_constraints = OFF")
        .execute(&mut *damaged)
        .await
        .expect("restore constraints");
    drop(damaged);
    assert!(matches!(
        store.read_accepted_account_key_put(request.account_id.into_bytes()).await,
        Err(AccountKeyStoreError::CorruptRow(_))
    ));
    pool_close::close(store.pool()).await;
    remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (scoplen_store::PostgresStore, sqlx::PgPool, String) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL fixture URL");
    let pool = sqlx::PgPool::connect(&database).await.expect("fixture pool");
    let schema = format!("accepted_put_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}")).execute(&pool).await.expect("owned schema");
    let mut url = url::Url::parse(&database).expect("database URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    let store = scoplen_store::PostgresStore::connect(url.as_str()).await.expect("store");
    (store, pool, schema)
}

#[cfg(feature = "postgres-integration")]
async fn cleanup_postgres(store: scoplen_store::PostgresStore, pool: sqlx::PgPool, schema: String) {
    store.pool().close().await;
    sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
        .execute(&pool)
        .await
        .expect("remove owned schema");
    pool.close().await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_accepted_put_lifecycle_and_cas() {
    let (store, pool, schema) = postgres_fixture().await;
    contract!(store, true, seed_postgres);
    cleanup_postgres(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_accepted_put_rejects_damaged_evidence_and_projection() {
    let (store, pool, schema) = postgres_fixture().await;
    corruption!(store, true, seed_postgres);
    cleanup_postgres(store, pool, schema).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_accepted_put_reads_projection_after_waiting_for_the_account_writer() {
    let (store, pool, schema) = postgres_fixture().await;
    let request = fixture();
    seed_postgres(store.pool(), &request, true).await;
    let mut writer = store.pool().begin().await.expect("writer");
    sqlx::query("SELECT pg_advisory_xact_lock(hashtextextended(encode($1, 'hex'), 0))")
        .bind(request.account_id.into_bytes().as_slice())
        .execute(&mut *writer)
        .await
        .expect("account writer lock");
    sqlx::query(
        "UPDATE sync_account_key_bundles SET accepted_put_cbor = NULL WHERE account_id = $1",
    )
    .bind(request.account_id.into_bytes().as_slice())
    .execute(&mut *writer)
    .await
    .expect("invalidate evidence");
    let mut reader = Box::pin(store.read_accepted_account_key_put(request.account_id.into_bytes()));
    assert!(tokio::time::timeout(Duration::from_millis(50), &mut reader).await.is_err());
    writer.commit().await.expect("committed invalidation");
    assert!(reader.await.expect("post-lock evidence read").is_none());
    cleanup_postgres(store, pool, schema).await;
}
