// SPDX-License-Identifier: AGPL-3.0-only

use scoplen_store::{
    AuditCheckpoint, AuditStoreError, RelationalStore, SqliteStore,
    append_audit_event_in_transaction,
};
use std::{path::PathBuf, time::Duration};

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-audit-{}", uuid::Uuid::new_v4()));
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

async fn insert_organization(store: &SqliteStore, organization_id: [u8; 16]) {
    sqlx::query("INSERT INTO organizations (id, name, created_at_ms) VALUES (?, ?, ?)")
        .bind(organization_id.as_slice())
        .bind("audit test")
        .bind(1_i64)
        .execute(store.pool())
        .await
        .expect("insert organization");
}

#[tokio::test]
async fn audit_events_chain_and_checkpoint_are_durable_and_idempotent() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let organization = [7; 16];
    insert_organization(&store, organization).await;

    let first = store.append_audit_event(organization, b"first", 1).await.expect("first event");
    let second = store.append_audit_event(organization, b"second", 2).await.expect("second event");
    assert_eq!(first.sequence, 1);
    assert_eq!(second.sequence, 2);
    assert_eq!(second.previous_hash, first.event_hash);
    assert_eq!(
        store.verify_audit_chain(organization).await.expect("verify chain"),
        second.event_hash
    );

    let checkpoint = AuditCheckpoint {
        organization_id: organization,
        sequence: second.sequence,
        head_hash: second.event_hash,
        signature: [9; 64],
        signed_at_ms: 3,
    };
    store.write_audit_checkpoint(&checkpoint).await.expect("write checkpoint");
    store.write_audit_checkpoint(&checkpoint).await.expect("repeat checkpoint");
    let mut conflict = checkpoint.clone();
    conflict.signature[0] = 8;
    assert!(matches!(
        store.write_audit_checkpoint(&conflict).await,
        Err(AuditStoreError::CheckpointConflict)
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

#[tokio::test]
async fn audit_transaction_rollback_and_integrity_failures_leave_state_unchanged() {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let organization = [8; 16];
    insert_organization(&store, organization).await;

    let mut transaction = store.pool().begin().await.expect("begin transaction");
    append_audit_event_in_transaction(&mut transaction, organization, b"rolled back", 1)
        .await
        .expect("append in transaction");
    transaction.rollback().await.expect("rollback");
    assert_eq!(store.verify_audit_chain(organization).await.expect("empty chain"), [0; 32]);

    assert!(matches!(
        store.append_audit_event(organization, b"", 1).await,
        Err(AuditStoreError::Primitive(_))
    ));
    assert!(matches!(
        store.append_audit_event(organization, b"event", 0).await,
        Err(AuditStoreError::Primitive(_))
    ));
    let wrong = AuditCheckpoint {
        organization_id: organization,
        sequence: 1,
        head_hash: [4; 32],
        signature: [5; 64],
        signed_at_ms: 2,
    };
    assert!(matches!(
        store.write_audit_checkpoint(&wrong).await,
        Err(AuditStoreError::CheckpointMismatch)
    ));

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}
