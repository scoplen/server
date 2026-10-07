// SPDX-License-Identifier: AGPL-3.0-only

use std::{collections::HashSet, path::PathBuf, sync::Arc, time::Duration};

use futures_util::future::join_all;
use scoplen_store::{JobQueueError, RelationalStore, SqliteStore};

use scoplen_store::jobs::{
    Job, MAX_JOB_ERROR_BYTES, MAX_JOB_KIND_BYTES, MAX_JOB_LEASE_MS, MAX_JOB_OWNER_BYTES,
    MAX_JOB_PAYLOAD_BYTES,
};

fn test_directory() -> PathBuf {
    let path = std::env::temp_dir().join(format!("scoplen-jobs-{}", uuid::Uuid::new_v4()));
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

async fn open_store() -> (PathBuf, SqliteStore) {
    let directory = test_directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    (directory, store)
}

async fn close_store(directory: PathBuf, store: SqliteStore) {
    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}

fn job_id(value: u8) -> [u8; 16] {
    [value; 16]
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .expect("clock after epoch")
        .as_millis()
        .try_into()
        .expect("current timestamp fits SQLite integer")
}

fn assert_job(job: &Job, id: u8, available_at_ms: i64, attempts: u64, owner: Option<&str>) {
    assert_eq!(job.id, job_id(id));
    assert_eq!(job.kind, "sync-retention");
    assert_eq!(job.payload, vec![id]);
    assert_eq!(job.available_at_ms, available_at_ms);
    assert_eq!(job.attempts, attempts);
    assert_eq!(job.lease_owner.as_deref(), owner);
}

#[tokio::test]
async fn enqueue_is_durable_and_duplicate_ids_are_rejected() {
    let (directory, store) = open_store().await;
    store.enqueue_job(job_id(1), "sync-retention", &[1], 100).await.expect("enqueue job");
    let job = store.get_job(job_id(1)).await.expect("read queued job");
    assert_job(&job, 1, 100, 0, None);
    assert!(job.lease_owner.is_none());
    assert!(job.lease_until_ms.is_none());
    assert!(job.finished_at_ms.is_none());

    let duplicate = store.enqueue_job(job_id(1), "other", &[], 100).await;
    assert!(matches!(duplicate, Err(JobQueueError::Constraint(_))));
    let unchanged = store.get_job(job_id(1)).await.expect("read original job");
    assert_eq!(unchanged.kind, "sync-retention");
    assert_eq!(unchanged.payload, vec![1]);

    close_store(directory, store).await;
}

#[tokio::test]
async fn enqueue_if_absent_deduplicates_unfinished_payloads_and_allows_retry_after_completion() {
    let (directory, store) = open_store().await;
    assert!(
        store
            .enqueue_job_if_absent(job_id(1), "sync-retention", &[7], 100)
            .await
            .expect("enqueue first")
    );
    assert!(
        !store
            .enqueue_job_if_absent(job_id(2), "sync-retention", &[7], 200)
            .await
            .expect("deduplicate pending")
    );
    assert!(
        store
            .enqueue_job_if_absent(job_id(3), "sync-retention", &[8], 200)
            .await
            .expect("different payload")
    );
    let claim_at = now_ms();
    let first = store
        .claim_job_kind("sync-retention", "worker", claim_at, 100_000)
        .await
        .expect("claim retention")
        .expect("retention job");
    store.complete_job(first.id, "worker", claim_at + 1).await.expect("complete retention");
    assert!(
        store
            .enqueue_job_if_absent(job_id(4), "sync-retention", &[7], 300)
            .await
            .expect("enqueue completed payload")
    );
    assert!(
        store
            .claim_job_kind("other", "worker", 1_000, 1_000)
            .await
            .expect("other kind claim")
            .is_none()
    );
    close_store(directory, store).await;
}

#[tokio::test]
async fn claims_follow_availability_order_and_update_attempts() {
    let (directory, store) = open_store().await;
    store.enqueue_job(job_id(1), "sync-retention", &[1], 200).await.expect("enqueue later job");
    store.enqueue_job(job_id(2), "sync-retention", &[2], 100).await.expect("enqueue first job");
    store.enqueue_job(job_id(3), "sync-retention", &[3], 100).await.expect("enqueue tie-break job");

    let first = store.claim_job("worker-a", 150, 1_000).await.expect("claim first");
    assert_job(first.as_ref().expect("first job"), 2, 100, 1, Some("worker-a"));
    let second = store.claim_job("worker-a", 150, 1_000).await.expect("claim second");
    assert_job(second.as_ref().expect("second job"), 3, 100, 1, Some("worker-a"));
    let third = store.claim_job("worker-a", 150, 1_000).await.expect("no future job");
    assert!(third.is_none());

    let future = store.claim_job("worker-a", 200, 1_000).await.expect("claim future job");
    assert_job(future.as_ref().expect("future job"), 1, 200, 1, Some("worker-a"));

    close_store(directory, store).await;
}

#[tokio::test]
async fn expired_leases_are_requeued_and_old_owner_cannot_write() {
    let (directory, store) = open_store().await;
    let now = now_ms();
    store.enqueue_job(job_id(1), "sync-retention", &[1], now).await.expect("enqueue job");
    let claimed = store.claim_job("worker-a", now, 50).await.expect("claim job");
    let claimed = claimed.expect("job is available");
    assert_eq!(claimed.lease_until_ms, Some(now + 50));

    assert!(matches!(
        store.renew_job(job_id(1), "worker-a", now + 50, 50).await,
        Err(JobQueueError::LeaseLost)
    ));
    assert!(matches!(
        store.complete_job(job_id(1), "worker-a", now + 50).await,
        Err(JobQueueError::LeaseLost)
    ));
    assert!(matches!(
        store.fail_job(job_id(1), "worker-a", now + 50, now + 100, "late").await,
        Err(JobQueueError::LeaseLost)
    ));

    assert_eq!(store.requeue_expired_jobs(now + 50).await.expect("requeue expired"), 1);
    let reclaimed = store.claim_job("worker-b", now + 50, 100).await.expect("reclaim job");
    let reclaimed = reclaimed.expect("expired job is available");
    assert_job(&reclaimed, 1, now, 2, Some("worker-b"));

    store.complete_job(job_id(1), "worker-b", now + 75).await.expect("complete live lease");
    let completed = store.get_job(job_id(1)).await.expect("read completed job");
    assert_eq!(completed.finished_at_ms, Some(now + 75));
    assert!(completed.lease_owner.is_none());
    assert!(completed.lease_until_ms.is_none());
    assert!(store.claim_job("worker-c", now + 100, 100).await.expect("empty queue").is_none());
    assert_eq!(store.requeue_expired_jobs(now + 200).await.expect("requeue completed"), 0);

    close_store(directory, store).await;
}

#[tokio::test]
async fn renew_and_failure_require_owner_and_preserve_retry_detail() {
    let (directory, store) = open_store().await;
    store.enqueue_job(job_id(1), "sync-retention", &[1], 100).await.expect("enqueue job");
    store.claim_job("worker-a", 100, 100).await.expect("claim job");

    assert!(matches!(
        store.renew_job(job_id(1), "worker-b", 120, 100).await,
        Err(JobQueueError::LeaseLost)
    ));
    store.renew_job(job_id(1), "worker-a", 120, 100).await.expect("renew live lease");
    let renewed = store.get_job(job_id(1)).await.expect("read renewed job");
    assert_eq!(renewed.lease_until_ms, Some(220));

    assert!(matches!(
        store.fail_job(job_id(1), "worker-b", 130, 200, "denied").await,
        Err(JobQueueError::LeaseLost)
    ));
    store
        .fail_job(job_id(1), "worker-a", 130, 300, "upstream timeout")
        .await
        .expect("record failure");
    let failed = store.get_job(job_id(1)).await.expect("read failed job");
    assert_eq!(failed.available_at_ms, 300);
    assert_eq!(failed.last_error.as_deref(), Some("upstream timeout"));
    assert!(failed.lease_owner.is_none());
    assert!(failed.lease_until_ms.is_none());
    assert!(store.claim_job("worker-c", 299, 100).await.expect("not ready").is_none());
    let retry = store.claim_job("worker-c", 300, 100).await.expect("retry claim");
    assert_job(retry.as_ref().expect("retry is available"), 1, 300, 2, Some("worker-c"));

    close_store(directory, store).await;
}

#[tokio::test]
async fn queue_rejects_invalid_bounds_before_writing() {
    let (directory, store) = open_store().await;
    assert!(matches!(
        store.enqueue_job(job_id(1), "", &[], 0).await,
        Err(JobQueueError::InvalidKind)
    ));
    assert!(matches!(
        store.enqueue_job(job_id(1), &"k".repeat(MAX_JOB_KIND_BYTES + 1), &[], 0).await,
        Err(JobQueueError::InvalidKind)
    ));
    assert!(matches!(
        store.enqueue_job(job_id(1), "valid", &vec![0; MAX_JOB_PAYLOAD_BYTES + 1], 0).await,
        Err(JobQueueError::PayloadTooLarge)
    ));
    assert!(matches!(
        store.enqueue_job(job_id(1), "valid", &[], -1).await,
        Err(JobQueueError::InvalidTimestamp)
    ));
    store.enqueue_job(job_id(1), "valid", &[], 0).await.expect("enqueue bounded job");
    assert!(matches!(store.claim_job("", 0, 1).await, Err(JobQueueError::InvalidOwner)));
    assert!(matches!(
        store.claim_job(&"o".repeat(MAX_JOB_OWNER_BYTES + 1), 0, 1).await,
        Err(JobQueueError::InvalidOwner)
    ));
    assert!(matches!(store.claim_job("worker", 0, 0).await, Err(JobQueueError::InvalidLease)));
    assert!(matches!(
        store.claim_job("worker", 0, MAX_JOB_LEASE_MS + 1).await,
        Err(JobQueueError::InvalidLease)
    ));
    let claimed = store.claim_job("worker", 0, 1).await.expect("claim bounded job");
    assert!(claimed.is_some());
    assert!(matches!(
        store.fail_job(job_id(1), "worker", 0, 1, &"e".repeat(MAX_JOB_ERROR_BYTES + 1)).await,
        Err(JobQueueError::ErrorTooLarge)
    ));

    close_store(directory, store).await;
}

#[tokio::test]
async fn concurrent_claims_never_return_the_same_job() {
    let (directory, store) = open_store().await;
    for id in 1..=4 {
        store
            .enqueue_job(job_id(id), "sync-retention", &[id], 0)
            .await
            .expect("enqueue concurrent job");
    }
    let store = Arc::new(store);
    let claims = (0..12)
        .map(|worker| {
            let store = Arc::clone(&store);
            tokio::spawn(async move {
                store
                    .claim_job(&format!("worker-{worker}"), 0, 1_000)
                    .await
                    .expect("concurrent claim")
            })
        })
        .collect::<Vec<_>>();
    let results = join_all(claims)
        .await
        .into_iter()
        .filter_map(|result| result.expect("claim task completes"))
        .collect::<Vec<_>>();
    assert_eq!(results.len(), 4);
    let ids = results.iter().map(|job| job.id).collect::<HashSet<_>>();
    assert_eq!(ids.len(), results.len());

    store.pool().close().await;
    drop(store);
    remove_test_directory(directory).await;
}
