// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_store::pairing::PairingCleanupReport;
use std::{path::PathBuf, time::Duration};

struct Fixture {
    directory: Option<PathBuf>,
    #[cfg(feature = "postgres-integration")]
    postgres: Option<(sqlx::PgPool, String, String)>,
}

impl Fixture {
    async fn close(self) {
        if let Some(directory) = self.directory {
            support::remove_test_directory(directory).await;
        }
        #[cfg(feature = "postgres-integration")]
        if let Some((pool, schema, _)) = self.postgres {
            assert!(schema.starts_with("pairing_maintenance_"));
            assert!(schema.bytes().all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'));
            sqlx::query(&format!("DROP SCHEMA {schema} CASCADE"))
                .execute(&pool)
                .await
                .expect("remove owned maintenance schema");
            pool_close::close(&pool).await;
        }
    }
}

async fn sqlite_fixture() -> (SqliteStore, Fixture) {
    let (store, directory) = sqlite_open().await;
    (
        store,
        Fixture {
            directory,
            #[cfg(feature = "postgres-integration")]
            postgres: None,
        },
    )
}

async fn sqlite_reopen(fixture: &Fixture) -> SqliteStore {
    SqliteStore::open(&fixture.directory.as_ref().expect("SQLite directory").join("scoplen.sqlite"))
        .await
        .expect("independent SQLite store")
}

#[cfg(feature = "postgres-integration")]
async fn postgres_fixture() -> (scoplen_store::PostgresStore, Fixture) {
    let database = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL test URL");
    let admin = sqlx::PgPool::connect(&database).await.expect("schema administration pool");
    let schema = format!("pairing_maintenance_{}", Uuid::now_v7().simple());
    sqlx::query(&format!("CREATE SCHEMA {schema}"))
        .execute(&admin)
        .await
        .expect("owned maintenance schema");
    let mut url = url::Url::parse(&database).expect("PostgreSQL fixture URL");
    url.query_pairs_mut().append_pair("options", &format!("-csearch_path={schema}"));
    url.query_pairs_mut().append_pair("application_name", &schema);
    let store =
        scoplen_store::PostgresStore::connect(url.as_str()).await.expect("PostgreSQL store");
    (store, Fixture { directory: None, postgres: Some((admin, schema, url.to_string())) })
}

#[cfg(feature = "postgres-integration")]
async fn postgres_reopen(fixture: &Fixture) -> scoplen_store::PostgresStore {
    let (_, _, url) = fixture.postgres.as_ref().expect("PostgreSQL fixture");
    scoplen_store::PostgresStore::connect(url).await.expect("independent PostgreSQL store")
}

fn now_ms() -> i64 {
    i64::try_from(
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_millis(),
    )
    .expect("timestamp")
}

async fn sqlite_wait_for_cleanup(
    store: &SqliteStore,
    _fixture: &Fixture,
    _blocker_pid: i32,
    task: &tokio::task::JoinHandle<Result<PairingCleanupReport, PairingStoreError>>,
) {
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            // The holder owns one connection. The cleanup must acquire another before
            // the fixture advances expiry, rather than relying on a scheduling delay.
            let acquired =
                usize::try_from(store.pool().size()).expect("pool size") - store.pool().num_idle();
            if acquired >= 2 {
                return;
            }
            assert!(!task.is_finished(), "cleanup remains blocked by the writer");
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("cleanup acquired its SQLite connection");
}

#[cfg(feature = "postgres-integration")]
async fn postgres_wait_for_cleanup(
    store: &scoplen_store::PostgresStore,
    fixture: &Fixture,
    blocker_pid: i32,
    task: &tokio::task::JoinHandle<Result<PairingCleanupReport, PairingStoreError>>,
) {
    let (_, marker, _) = fixture.postgres.as_ref().expect("PostgreSQL fixture");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let waiting: bool = sqlx::query_scalar(
                "SELECT EXISTS (SELECT 1 FROM pg_stat_activity WHERE application_name=$2
                 AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)))",
            )
            .bind(blocker_pid)
            .bind(marker)
            .fetch_one(store.pool())
            .await
            .expect("observe this cleanup's pairing lock waiter");
            if waiting {
                return;
            }
            assert!(!task.is_finished(), "cleanup remains blocked by the pairing lock");
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("cleanup reached its PostgreSQL serialization lock");
}

macro_rules! maintenance_tests {
    ($module:ident, $store:ty, $open:ident, $reopen:ident, $wait:ident, $postgres:literal) => {
        mod $module {
            use super::*;

            fn sql(source: &str) -> String {
                if !$postgres { return source.to_owned(); }
                let mut n = 0;
                source.chars().map(|c| if c == '?' { n += 1; format!("${n}") } else { c.to_string() }).collect()
            }

            async fn seed(store: &$store, count: usize, state: &str, expires: i64, retained: i64) -> Vec<Uuid> {
                let mut tx = store.pool().begin().await.expect("seed transaction");
                let mut ids = Vec::new();
                for _ in 0..count {
                    let id = Uuid::now_v7();
                    let live = state == "waiting";
                    sqlx::query(&sql("INSERT INTO pairing_sessions (pairing_id,trusted_origin,responder_device_id,capability_digest,created_at_ms,expires_at_ms,retain_until_ms,state,slot_count,payload_bytes) VALUES (?,?,?,?,?,?,?,?,1,?)"))
                        .bind(id.as_bytes().as_slice()).bind(ORIGIN).bind(Uuid::now_v7().as_bytes().as_slice())
                        .bind([7_u8;32].as_slice()).bind(expires - 300_000).bind(expires).bind(retained)
                        .bind(state).bind(i64::from(live))
                        .execute(&mut *tx).await.expect("seed bounded session");
                    sqlx::query(&sql("INSERT INTO pairing_slots (pairing_id,slot_index,payload,payload_digest) VALUES (?,0,?,?)"))
                        .bind(id.as_bytes().as_slice()).bind(live.then_some(vec![9_u8]))
                        .bind([8_u8;32].as_slice()).execute(&mut *tx).await.expect("seed relay slot");
                    ids.push(id);
                }
                tx.commit().await.expect("commit maintenance fixture");
                ids
            }

            async fn audit_count(store: &$store) -> u64 {
                store.deployment_audit_head().await.expect("audit head").map_or(0, |head| head.sequence)
            }

            #[tokio::test]
            async fn maintenance_without_pairing_requests_erases_payloads_and_preserves_live_receipts() {
                let (store, fixture) = $open().await;
                let request = crate::$module::fixture(&store).await;
                let (context, _, complete) = crate::$module::ready(&store, &request).await;
                let receipt = store.complete_pairing(ORIGIN,context.pairing_id,&principal(&request),&complete,source()).await.expect("completed pairing");
                let retained: i64 = sqlx::query_scalar(&sql("SELECT retain_until_ms FROM pairing_sessions WHERE pairing_id=?"))
                    .bind(context.pairing_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("receipt retention");
                let now = now_ms();
                let live = seed(&store,1,"waiting",now+300_000,now+86_700_000).await[0];
                let expired = seed(&store,1,"waiting",now-1,now+86_400_000).await[0];
                let removed = seed(&store,1,"cancelled",now-300_000,now-1).await[0];
                let before = audit_count(&store).await;
                assert_eq!(store.cleanup_pairings().await.expect("independent maintenance"),PairingCleanupReport {expired_sessions:1,removed_sessions:1});
                let row = sqlx::query(&sql("SELECT state,payload_bytes,retain_until_ms FROM pairing_sessions WHERE pairing_id=?"))
                    .bind(expired.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("expired metadata");
                assert_eq!(row.get::<String,_>("state"),"expired");
                assert_eq!(row.get::<i64,_>("payload_bytes"),0);
                assert_eq!(row.get::<i64,_>("retain_until_ms"),now+86_400_000);
                let payload: Option<Vec<u8>> = sqlx::query_scalar(&sql("SELECT payload FROM pairing_slots WHERE pairing_id=?"))
                    .bind(expired.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("erased payload");
                assert_eq!(payload,None);
                let live_payload: Option<Vec<u8>> = sqlx::query_scalar(&sql("SELECT payload FROM pairing_slots WHERE pairing_id=?"))
                    .bind(live.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("live payload");
                assert_eq!(live_payload,Some(vec![9]));
                let removed_slots: i64 = sqlx::query_scalar(&sql("SELECT COUNT(*) FROM pairing_slots WHERE pairing_id=?"))
                    .bind(removed.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("removed slots");
                assert_eq!(removed_slots,0);
                assert_eq!(audit_count(&store).await,before+2);
                assert_eq!(store.cleanup_pairings().await.expect("idempotent maintenance"),PairingCleanupReport::default());
                assert_eq!(store.complete_pairing(ORIGIN,context.pairing_id,&principal(&request),&complete,source()).await.expect("unchanged receipt"),receipt);
                let after: i64 = sqlx::query_scalar(&sql("SELECT retain_until_ms FROM pairing_sessions WHERE pairing_id=?"))
                    .bind(context.pairing_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("fixed receipt retention");
                assert_eq!(after,retained);
                assert_eq!(audit_count(&store).await,before+2);
                sqlx::query(&sql("UPDATE pairing_sessions SET created_at_ms=?,expires_at_ms=?,retain_until_ms=? WHERE pairing_id=?"))
                    .bind(now-90_000_000).bind(now-89_700_000).bind(now-1)
                    .bind(context.pairing_id.as_bytes().as_slice()).execute(store.pool()).await.expect("age completed receipt beyond its fixed retention");
                assert_eq!(store.cleanup_pairings().await.expect("remove elapsed receipt"),PairingCleanupReport {expired_sessions:0,removed_sessions:1});
                let receipt_rows:i64=sqlx::query_scalar(&sql("SELECT COUNT(*) FROM pairing_sessions WHERE pairing_id=?"))
                    .bind(context.pairing_id.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("removed receipt");
                assert_eq!(receipt_rows,0);
                assert_eq!(audit_count(&store).await,before+3);
                store.verify_deployment_audit_chain().await.expect("valid maintenance audit chain");
                pool_close::close(store.pool()).await;
                fixture.close().await;
            }

            #[tokio::test]
            async fn maintenance_processes_only_one_bounded_batch_and_resumes_next_pass() {
                let (store, fixture) = $open().await;
                let now = now_ms();
                seed(&store,257,"waiting",now-1,now+86_400_000).await;
                seed(&store,257,"cancelled",now-300_000,now-1).await;
                assert_eq!(store.cleanup_pairings().await.expect("first finite batch"),PairingCleanupReport {expired_sessions:256,removed_sessions:256});
                let waiting: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing_sessions WHERE state='waiting'").fetch_one(store.pool()).await.expect("remaining waiting session");
                let cancelled: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM pairing_sessions WHERE state='cancelled'").fetch_one(store.pool()).await.expect("remaining terminal session");
                assert_eq!((waiting,cancelled),(1,1));
                assert_eq!(audit_count(&store).await,512);
                assert_eq!(store.cleanup_pairings().await.expect("next finite batch"),PairingCleanupReport {expired_sessions:1,removed_sessions:1});
                assert_eq!(audit_count(&store).await,514);
                assert_eq!(store.cleanup_pairings().await.expect("empty pass"),PairingCleanupReport::default());
                pool_close::close(store.pool()).await;
                fixture.close().await;
            }

            #[tokio::test]
            async fn independent_maintenance_pools_commit_each_transition_once() {
                let (store, fixture) = $open().await;
                let peer = $reopen(&fixture).await;
                let now = now_ms();
                seed(&store,300,"waiting",now-1,now+86_400_000).await;
                let (first,second) = tokio::join!(store.cleanup_pairings(),peer.cleanup_pairings());
                let first=first.expect("first maintenance pool");
                let second=second.expect("second maintenance pool");
                assert!(first.expired_sessions<=256 && second.expired_sessions<=256);
                assert_eq!(first.expired_sessions+second.expired_sessions,300);
                assert_eq!(first.removed_sessions+second.removed_sessions,0);
                assert_eq!(audit_count(&store).await,300);
                assert_eq!(peer.cleanup_pairings().await.expect("no duplicate transitions"),PairingCleanupReport::default());
                store.verify_deployment_audit_chain().await.expect("serialized audit chain");
                pool_close::close(peer.pool()).await;
                pool_close::close(store.pool()).await;
                fixture.close().await;
            }

            #[tokio::test]
            async fn failed_removal_audit_rolls_back_earlier_expiry_and_its_audit() {
                let (store, fixture) = $open().await;
                let now = now_ms();
                let expired=seed(&store,1,"waiting",now-1,now+86_400_000).await[0];
                seed(&store,1,"cancelled",now-300_000,now-1).await;
                let reject=if $postgres {
                    "CREATE FUNCTION reject_maintenance_removal() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN IF get_byte(NEW.event_bytes,octet_length('spl-pairing-audit-v1'))=7 THEN RAISE EXCEPTION 'fixture audit failure'; END IF; RETURN NEW; END; $$; CREATE TRIGGER reject_maintenance_removal BEFORE INSERT ON deployment_audit_events FOR EACH ROW EXECUTE FUNCTION reject_maintenance_removal()"
                } else {
                    "CREATE TRIGGER reject_maintenance_removal BEFORE INSERT ON deployment_audit_events WHEN substr(NEW.event_bytes,length('spl-pairing-audit-v1')+1,1)=x'07' BEGIN SELECT RAISE(ABORT,'fixture audit failure'); END"
                };
                sqlx::raw_sql(reject).execute(store.pool()).await.expect("inject removal audit failure");
                assert_eq!(store.cleanup_pairings().await,Err(PairingStoreError::Audit));
                let row=sqlx::query(&sql("SELECT state,payload_bytes FROM pairing_sessions WHERE pairing_id=?"))
                    .bind(expired.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("expiry rollback");
                assert_eq!(row.get::<String,_>("state"),"waiting");
                assert_eq!(row.get::<i64,_>("payload_bytes"),1);
                let payload:Option<Vec<u8>>=sqlx::query_scalar(&sql("SELECT payload FROM pairing_slots WHERE pairing_id=?"))
                    .bind(expired.as_bytes().as_slice()).fetch_one(store.pool()).await.expect("payload rollback");
                assert_eq!(payload,Some(vec![9]));
                let rows:i64=sqlx::query_scalar("SELECT COUNT(*) FROM pairing_sessions").fetch_one(store.pool()).await.expect("retained sessions");
                assert_eq!(rows,2);
                assert_eq!(audit_count(&store).await,0);
                let remove=if $postgres {"DROP TRIGGER reject_maintenance_removal ON deployment_audit_events; DROP FUNCTION reject_maintenance_removal()"}else{"DROP TRIGGER reject_maintenance_removal"};
                sqlx::raw_sql(remove).execute(store.pool()).await.expect("restore audit");
                assert_eq!(store.cleanup_pairings().await.expect("explicit next maintenance pass"),PairingCleanupReport {expired_sessions:1,removed_sessions:1});
                pool_close::close(store.pool()).await;
                fixture.close().await;
            }

            #[tokio::test]
            async fn maintenance_samples_time_after_acquiring_the_serialization_lock() {
                let (store, fixture) = $open().await;
                let now=now_ms();
                let id=seed(&store,1,"waiting",now+300_000,now+86_400_000).await[0];
                let mut holder=store.pool().begin_with(if $postgres {"BEGIN"}else{"BEGIN IMMEDIATE"}).await.expect("hold maintenance lock");
                if $postgres {sqlx::query("SELECT pg_advisory_xact_lock(1935897196,114)").execute(&mut *holder).await.expect("pairing serialization lock");}
                let blocker_pid = if $postgres {sqlx::query_scalar("SELECT pg_backend_pid()").fetch_one(&mut *holder).await.expect("blocker pid")}else{0};
                let (entered,started)=tokio::sync::oneshot::channel();
                let attempting=store.clone();
                let task=tokio::spawn(async move {entered.send(()).expect("start observer");attempting.cleanup_pairings().await});
                started.await.expect("maintenance started");
                $wait(&store,&fixture,blocker_pid,&task).await;
                let expires=now_ms()+200;
                sqlx::query(&sql("UPDATE pairing_sessions SET created_at_ms=?,expires_at_ms=? WHERE pairing_id=?"))
                    .bind(expires-300_000).bind(expires).bind(id.as_bytes().as_slice())
                    .execute(&mut *holder).await.expect("set expiry after maintenance starts waiting");
                let remaining=u64::try_from((expires+100-now_ms()).max(0)).expect("remaining real lifetime");
                tokio::time::sleep(Duration::from_millis(remaining)).await;
                holder.commit().await.expect("unlock after expiry");
                assert_eq!(task.await.expect("maintenance task").expect("lock-current time"),PairingCleanupReport {expired_sessions:1,removed_sessions:0});
                pool_close::close(store.pool()).await;
                fixture.close().await;
            }
        }
    };
}

maintenance_tests!(
    sqlite,
    SqliteStore,
    sqlite_fixture,
    sqlite_reopen,
    sqlite_wait_for_cleanup,
    false
);

#[cfg(feature = "postgres-integration")]
maintenance_tests!(
    postgres,
    scoplen_store::PostgresStore,
    postgres_fixture,
    postgres_reopen,
    postgres_wait_for_cleanup,
    true
);
