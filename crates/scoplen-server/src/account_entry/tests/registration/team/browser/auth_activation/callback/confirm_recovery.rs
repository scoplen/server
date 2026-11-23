// SPDX-License-Identifier: AGPL-3.0-only
//! A lost activation confirmation is recoverable only through its original writer receipt.

use std::sync::atomic::Ordering;

use super::*;
use crate::test_lost_commit::LostCommitProxy;

pub(super) async fn lose_commit_ack_at_write(
    pool: &sqlx::PgPool,
    application: &str,
    proxy: &LostCommitProxy,
    lock_table: &str,
    write_query: &str,
    request: impl Future<Output = Reply>,
) -> Reply {
    let mut lock = pool.begin().await.unwrap();
    sqlx::query(lock_table).execute(&mut *lock).await.unwrap();
    let holder: i32 =
        sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *lock).await.unwrap();
    let dropped = proxy.dropped.load(Ordering::SeqCst);
    let release = async {
        tokio::time::timeout(Duration::from_secs(10), async {
            loop {
                let writing: bool = sqlx::query_scalar(
                    "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$1
                     AND $2=ANY(pg_blocking_pids(pid)) AND starts_with(query,$3))",
                )
                .bind(application)
                .bind(holder)
                .bind(write_query)
                .fetch_one(pool)
                .await
                .unwrap();
                if writing {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(10)).await;
            }
        })
        .await
        .expect("request reached its gated business write");
        proxy.armed.store(true, Ordering::SeqCst);
        lock.commit().await.unwrap();
    };
    let (reply, ()) = tokio::join!(request, release);
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), dropped + 1);
    reply
}

fn assert_unconfirmed(reply: &Reply, provider: &Provider) {
    changed_problem(reply, 503, "organization.commit_outcome_unknown", true);
    assert_eq!(reply.header("content-type"), Some("application/problem+json"));
    assert!(reply.header("etag").is_none() && reply.header("location").is_none());
    let value: serde_json::Value = serde_json::from_slice(&reply.body).unwrap();
    let fields = value.as_object().unwrap();
    assert_eq!(fields.len(), 8);
    for key in ["type", "status", "title", "detail", "instance", "code", "changed", "retryable"] {
        assert!(fields.contains_key(key), "missing problem field {key}");
    }
    let body = std::str::from_utf8(&reply.body).unwrap();
    let credentials = Provider::login_material().credentials;
    let secret = std::str::from_utf8(credentials.client_secret.as_bytes()).unwrap();
    assert!(!body.contains(secret) && !body.contains(&provider.issuer));
}

#[tokio::test]
async fn postgres_auth_activation_https_lost_confirm_commit_recovers_original_revision() {
    let (store, admin, schema, mut database) =
        crate::account_entry::tests::postgres_fixture().await;
    let application = format!("activate_confirm_{}", Uuid::new_v4().simple());
    database.query_pairs_mut().append_pair("application_name", &application);
    let proxy = LostCommitProxy::start(database.as_str()).await;
    let proxied = scoplen_store::PostgresStore::connect(&proxy.database_url).await.unwrap();
    let f = Fixture::start(AuthBackend::Postgres(Arc::new(proxied)), directory()).await;
    let provider = Provider::start(f.directory.join("lost-confirm"), ORIGIN).await;
    let tls = TlsFixture::start_with_enterprise_identity(&f, provider.settings.clone()).await;
    let owner = actor(&f, "activation-lost-confirm").await;
    let org = create_team(&f, &owner).await.id;
    let browser = login(&f, &owner.registration).await;
    let other_family = login(&f, &owner.registration).await;
    let navigation = begin(&f, &tls, &browser, &provider, org).await;
    check_callback(
        &visit(&tls, &navigation.target, &navigation.cookie).await,
        Some(navigation.cookie.split_once('=').unwrap().0),
    );
    let audit = f.count("SELECT count(*) FROM audit_events").await;
    let key = Uuid::now_v7().to_string();
    let empty = ("If-None-Match", "*");
    let attempt = &navigation.attempt;
    let unconfirmed = lose_commit_ack_at_write(
        store.pool(),
        &application,
        &proxy,
        "LOCK TABLE organization_auth_connection_receipts IN SHARE MODE",
        "INSERT INTO organization_auth_connection_receipts ",
        confirm(&tls, &browser, attempt, empty, &key),
    )
    .await;
    assert_unconfirmed(&unconfirmed, &provider);
    let root = format!("/api/v1/orgs/{org}/auth-connection");
    let installed = send(&tls, &other_family, "GET", &root, &[], &[]).await;
    let active = connection(&installed, org, ConnectionStatus::Active);
    assert_eq!(active.target, attempt.context.target);
    confirm(&tls, &other_family, attempt, empty, &key).await.problem(
        409,
        "organization.conflict",
        false,
    );
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_receipts").await, 1);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 1);

    // Change the current head before recovering. Reading the head cannot prove the historic result.
    let suspend = send(
        &tls,
        &other_family,
        "POST",
        &format!("{root}/suspend"),
        &[
            ("Origin", ORIGIN),
            ("If-Match", &active.etag()),
            ("Idempotency-Key", &Uuid::now_v7().to_string()),
        ],
        &[],
    )
    .await;
    let suspended = connection(&suspend, org, ConnectionStatus::Suspended);
    assert_ne!(active.id, suspended.id);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 2);
    let recovered = confirm(&tls, &browser, attempt, empty, &key).await;
    assert_eq!(connection(&recovered, org, ConnectionStatus::Active), active);
    assert_eq!(recovered.body, installed.body);
    let current = send(&tls, &browser, "GET", &root, &[], &[]).await;
    assert_eq!(connection(&current, org, ConnectionStatus::Suspended), suspended);
    assert_eq!(f.count("SELECT count(*) FROM organization_auth_connection_receipts").await, 2);
    assert_eq!(f.count("SELECT count(*) FROM audit_events").await, audit + 2);
    assert_eq!(provider.discoveries(), 1);
    assert_eq!(provider.counts(), [1, 1, 0]);
    provider.close().await;
    drop(tls);
    f.close().await;
    store.pool().close().await;
    drop(proxy);
    crate::account_entry::tests::postgres_cleanup(admin, schema).await;
}
