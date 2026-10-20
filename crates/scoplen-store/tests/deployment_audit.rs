// SPDX-License-Identifier: AGPL-3.0-only

use scoplen_store::{
    AuditStoreError, DeploymentAuditCheckpoint, RelationalStore, SqliteStore,
    append_deployment_audit_event_in_transaction,
};
use std::{path::PathBuf, time::Duration};

fn test_directory() -> PathBuf {
    let path =
        std::env::temp_dir().join(format!("scoplen-deployment-audit-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("create isolated test directory");
    path
}

async fn remove_test_directory(path: PathBuf) {
    for attempt in 0..20 {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => return,
            Err(error) if error.raw_os_error() == Some(32) && attempt < 19 => {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("remove test directory {}: {error}", path.display()),
        }
    }
}

#[tokio::test]
async fn sqlite_deployment_chain_is_independent_durable_and_redacted() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    assert!(store.deployment_audit_head().await.expect("empty head").is_none());
    assert!(store.verify_deployment_audit_chain().await.expect("empty chain").is_none());
    let first = store
        .append_deployment_audit_event(b"private-event-content", 1)
        .await
        .expect("first event");
    let second = store.append_deployment_audit_event(b"second", 2).await.expect("second event");
    assert_eq!(first.sequence, 1);
    assert_eq!(first.previous_hash, [0; 32]);
    assert_eq!(second.sequence, 2);
    assert_eq!(second.previous_hash, first.event_hash);
    assert!(!format!("{first:?}").contains("private-event-content"));
    assert_eq!(store.deployment_audit_head().await.expect("head").unwrap().sequence, 2);
    assert_eq!(
        store.verify_deployment_audit_chain().await.expect("verify").unwrap().head_hash,
        second.event_hash
    );
    let organization_count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM organizations")
        .fetch_one(store.pool())
        .await
        .expect("count organizations");
    assert_eq!(organization_count, 0);
    store.pool().close().await;
    drop(store);
    let reopened = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("reopen");
    assert_eq!(
        reopened.verify_deployment_audit_chain().await.expect("durable").unwrap().head_hash,
        second.event_hash
    );
    reopened.pool().close().await;
    drop(reopened);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_deployment_append_joins_caller_transaction_and_rolls_back() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let mut transaction = store.pool().begin().await.expect("begin deferred transaction");
    append_deployment_audit_event_in_transaction(&mut transaction, b"rolled-back", 1)
        .await
        .expect("append within transaction");
    transaction.rollback().await.expect("rollback");
    assert!(store.verify_deployment_audit_chain().await.expect("empty").is_none());
    let first = store.append_deployment_audit_event(b"committed", 2).await.expect("commit");
    assert_eq!(first.sequence, 1);
    assert!(matches!(
        store.append_deployment_audit_event(b"", 3).await,
        Err(AuditStoreError::Primitive(_))
    ));
    assert!(matches!(
        store.append_deployment_audit_event(b"event", 0).await,
        Err(AuditStoreError::Primitive(_))
    ));
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_concurrent_deployment_appends_are_gap_free_and_tamper_detected() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let mut tasks = Vec::new();
    for i in 0..20_u8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store.append_deployment_audit_event(&[i], i64::from(i) + 1).await.expect("append")
        }));
    }
    let mut sequences = Vec::new();
    for task in tasks {
        sequences.push(task.await.expect("task").sequence);
    }
    sequences.sort_unstable();
    assert_eq!(sequences, (1..=20).collect::<Vec<_>>());
    let head = store.deployment_audit_head().await.expect("head").expect("nonempty");
    assert_eq!(store.verify_deployment_audit_chain().await.expect("verify"), Some(head));
    sqlx::query("UPDATE deployment_audit_events SET event_bytes = ? WHERE sequence = 10")
        .bind(b"changed".as_slice())
        .execute(store.pool())
        .await
        .expect("tamper for verification test");
    let tamper_verification = store.verify_deployment_audit_chain().await;
    assert!(matches!(tamper_verification, Err(AuditStoreError::CorruptChain)));
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_deployment_checkpoint_is_current_idempotent_and_conflict_checked() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let first = store.append_deployment_audit_event(b"first", 1).await.expect("first");
    let verified_prefix =
        store.verify_deployment_audit_chain().await.expect("verify prefix").unwrap();
    let second = store.append_deployment_audit_event(b"second", 3).await.expect("later append");
    let checkpoint = DeploymentAuditCheckpoint {
        sequence: verified_prefix.sequence,
        head_hash: verified_prefix.head_hash,
        signature: [7; 64],
        signed_at_ms: 2,
    };
    store.write_deployment_audit_checkpoint(&checkpoint).await.expect("write");
    store.write_deployment_audit_checkpoint(&checkpoint).await.expect("same is idempotent");
    assert_eq!(
        store.latest_deployment_audit_checkpoint().await.expect("latest"),
        Some(checkpoint.clone())
    );
    let mut conflict = checkpoint.clone();
    conflict.signature[0] = 8;
    assert!(matches!(
        store.write_deployment_audit_checkpoint(&conflict).await,
        Err(AuditStoreError::CheckpointConflict)
    ));
    let mut wrong = checkpoint.clone();
    wrong.sequence += 1;
    assert!(matches!(
        store.write_deployment_audit_checkpoint(&wrong).await,
        Err(AuditStoreError::CheckpointMismatch)
    ));
    store.write_deployment_audit_checkpoint(&checkpoint).await.expect("historical replay");
    let advanced = DeploymentAuditCheckpoint {
        sequence: second.sequence,
        head_hash: second.event_hash,
        signature: [9; 64],
        signed_at_ms: 4,
    };
    assert!(matches!(
        store.write_deployment_audit_checkpoint(&advanced).await,
        Err(AuditStoreError::CheckpointDeferred)
    ));
    let advanced = DeploymentAuditCheckpoint { signed_at_ms: 3_600_002, ..advanced };
    store.write_deployment_audit_checkpoint(&advanced).await.expect("advanced prefix after hour");
    assert_eq!(store.latest_deployment_audit_checkpoint().await.expect("latest"), Some(advanced));
    assert_eq!(first.event_hash, checkpoint.head_hash);
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn sqlite_different_prefixes_racing_in_one_hour_write_one_checkpoint() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let first = store.append_deployment_audit_event(b"first", 1).await.expect("first");
    let second = store.append_deployment_audit_event(b"second", 2).await.expect("second");
    let candidate_a = DeploymentAuditCheckpoint {
        sequence: first.sequence,
        head_hash: first.event_hash,
        signature: [1; 64],
        signed_at_ms: 3_600_000,
    };
    let candidate_b = DeploymentAuditCheckpoint {
        sequence: second.sequence,
        head_hash: second.event_hash,
        signature: [2; 64],
        signed_at_ms: 3_600_000,
    };
    let writer_a = {
        let store = store.clone();
        tokio::spawn(async move { store.write_deployment_audit_checkpoint(&candidate_a).await })
    };
    let writer_b = {
        let store = store.clone();
        tokio::spawn(async move { store.write_deployment_audit_checkpoint(&candidate_b).await })
    };
    let results = [writer_a.await.expect("writer a"), writer_b.await.expect("writer b")];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AuditStoreError::CheckpointDeferred)))
            .count(),
        1
    );
    let checkpoint_count: i64 =
        sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_checkpoints")
            .fetch_one(store.pool())
            .await
            .expect("count checkpoints");
    assert_eq!(checkpoint_count, 1);
    assert!(store.verify_deployment_audit_chain().await.is_ok());
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_deployment_chain_concurrency_rollback_checkpoint_and_tamper() {
    use scoplen_store::{PostgresStore, append_deployment_audit_event_in_postgres_transaction};

    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let store = PostgresStore::connect(&database_url).await.expect("open PostgreSQL store");
    let baseline = store.verify_deployment_audit_chain().await.expect("baseline chain");
    let baseline_sequence = baseline.as_ref().map_or(0, |head| head.sequence);
    let first_checkpoint_at = store
        .latest_deployment_audit_checkpoint()
        .await
        .expect("baseline checkpoint")
        .map_or(20, |previous| {
            previous.signed_at_ms.checked_add(3_600_001).expect("test timestamp range")
        });
    let mut transaction = store.pool().begin().await.expect("begin transaction");
    append_deployment_audit_event_in_postgres_transaction(&mut transaction, b"rollback", 1)
        .await
        .expect("append in transaction");
    transaction.rollback().await.expect("rollback");
    assert_eq!(store.verify_deployment_audit_chain().await.expect("rolled back"), baseline);

    let mut tasks = Vec::new();
    for i in 0..16_u8 {
        let store = store.clone();
        tasks.push(tokio::spawn(async move {
            store.append_deployment_audit_event(&[i], i64::from(i) + 2).await.expect("append")
        }));
    }
    let mut sequences = Vec::new();
    for task in tasks {
        sequences.push(task.await.expect("task").sequence);
    }
    sequences.sort_unstable();
    assert_eq!(sequences, (baseline_sequence + 1..=baseline_sequence + 16).collect::<Vec<_>>());
    let head = store.deployment_audit_head().await.expect("head").expect("nonempty");
    assert_eq!(store.verify_deployment_audit_chain().await.expect("verify"), Some(head));
    let verified_prefix =
        store.verify_deployment_audit_chain().await.expect("verified prefix").unwrap();
    store.append_deployment_audit_event(b"later", 21).await.expect("append after verification");
    let checkpoint = DeploymentAuditCheckpoint {
        sequence: verified_prefix.sequence,
        head_hash: verified_prefix.head_hash,
        signature: [3; 64],
        signed_at_ms: first_checkpoint_at,
    };
    let mut writers = Vec::new();
    for _ in 0..4 {
        let store = store.clone();
        let checkpoint = checkpoint.clone();
        writers.push(tokio::spawn(async move {
            store.write_deployment_audit_checkpoint(&checkpoint).await.expect("concurrent same");
        }));
    }
    for writer in writers {
        writer.await.expect("writer");
    }
    let mut conflict = checkpoint.clone();
    conflict.signed_at_ms += 1;
    assert!(matches!(
        store.write_deployment_audit_checkpoint(&conflict).await,
        Err(AuditStoreError::CheckpointConflict)
    ));
    assert_eq!(store.latest_deployment_audit_checkpoint().await.expect("latest"), Some(checkpoint));
    verify_postgres_checkpoint_cadence_race(&store, first_checkpoint_at).await;
    verify_postgres_tamper(&store, baseline_sequence + 8).await;
    store.pool().close().await;
}

#[cfg(feature = "postgres-integration")]
async fn verify_postgres_checkpoint_cadence_race(
    store: &scoplen_store::PostgresStore,
    first_checkpoint_at: i64,
) {
    let prefix_a = store.append_deployment_audit_event(b"race a", 22).await.expect("race a");
    let prefix_b = store.append_deployment_audit_event(b"race b", 23).await.expect("race b");
    let race_checkpoint_at =
        first_checkpoint_at.checked_add(3_600_000).expect("test timestamp range");
    let candidate_a = DeploymentAuditCheckpoint {
        sequence: prefix_a.sequence,
        head_hash: prefix_a.event_hash,
        signature: [4; 64],
        signed_at_ms: race_checkpoint_at,
    };
    let candidate_b = DeploymentAuditCheckpoint {
        sequence: prefix_b.sequence,
        head_hash: prefix_b.event_hash,
        signature: [5; 64],
        signed_at_ms: race_checkpoint_at,
    };
    let writer_a = {
        let store = store.clone();
        tokio::spawn(async move { store.write_deployment_audit_checkpoint(&candidate_a).await })
    };
    let writer_b = {
        let store = store.clone();
        tokio::spawn(async move { store.write_deployment_audit_checkpoint(&candidate_b).await })
    };
    let results = [writer_a.await.expect("writer a"), writer_b.await.expect("writer b")];
    assert_eq!(results.iter().filter(|result| result.is_ok()).count(), 1);
    assert_eq!(
        results
            .iter()
            .filter(|result| matches!(result, Err(AuditStoreError::CheckpointDeferred)))
            .count(),
        1
    );
    let checkpoint_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM deployment_audit_checkpoints WHERE signed_at_ms = $1",
    )
    .bind(race_checkpoint_at)
    .fetch_one(store.pool())
    .await
    .expect("count same-hour checkpoints");
    assert_eq!(checkpoint_count, 1);
}

#[cfg(feature = "postgres-integration")]
async fn verify_postgres_tamper(store: &scoplen_store::PostgresStore, tampered_sequence: u64) {
    let original_previous: Vec<u8> =
        sqlx::query_scalar("SELECT previous_hash FROM deployment_audit_events WHERE sequence = $1")
            .bind(i64::try_from(tampered_sequence).expect("test sequence fits SQL"))
            .fetch_one(store.pool())
            .await
            .expect("read original previous hash");
    sqlx::query("UPDATE deployment_audit_events SET previous_hash = $1 WHERE sequence = $2")
        .bind(vec![1_u8; 32])
        .bind(i64::try_from(tampered_sequence).expect("test sequence fits SQL"))
        .execute(store.pool())
        .await
        .expect("tamper for verification test");
    let tamper_verification = store.verify_deployment_audit_chain().await;
    sqlx::query("UPDATE deployment_audit_events SET previous_hash = $1 WHERE sequence = $2")
        .bind(original_previous)
        .bind(i64::try_from(tampered_sequence).expect("test sequence fits SQL"))
        .execute(store.pool())
        .await
        .expect("restore test row");
    assert!(matches!(tamper_verification, Err(AuditStoreError::CorruptChain)));
    assert!(store.verify_deployment_audit_chain().await.is_ok());
}
