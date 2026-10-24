// SPDX-License-Identifier: AGPL-3.0-only

mod support;

use std::{
    path::PathBuf,
    sync::{
        Arc, Condvar, Mutex,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Wake, Waker},
    time::Duration,
};

use scoplen_store::{
    RelationalStore, SqliteStore,
    device_authentication::{DeviceAuthAdmission, DeviceAuthEndpoint},
};
use sqlx::{Connection, Sqlite, SqliteConnection, pool::PoolConnection};

const DEADLINE: Duration = Duration::from_secs(10);

#[derive(Default)]
struct GateState {
    entered: bool,
    released: bool,
}

#[derive(Default)]
struct Gate {
    state: Mutex<GateState>,
    changed: Condvar,
}

impl Gate {
    fn pause(&self) -> bool {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.entered = true;
        self.changed.notify_all();
        let (state, _) = self
            .changed
            .wait_timeout_while(state, DEADLINE, |state| !state.released)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        state.released
    }

    fn wait_for_entry(&self) {
        let state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        let (state, _) = self
            .changed
            .wait_timeout_while(state, DEADLINE, |state| !state.entered)
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        assert!(state.entered, "SQLite worker did not reach the controlled barrier");
    }

    fn release(&self) {
        let mut state = self.state.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        state.released = true;
        self.changed.notify_all();
    }
}

struct ReleaseOnDrop(Arc<Gate>);

impl Drop for ReleaseOnDrop {
    fn drop(&mut self) {
        self.0.release();
    }
}

struct PausedWake {
    gate: Arc<Gate>,
    used: AtomicBool,
}

impl Wake for PausedWake {
    fn wake(self: Arc<Self>) {
        self.wake_by_ref();
    }

    fn wake_by_ref(self: &Arc<Self>) {
        if !self.used.swap(true, Ordering::SeqCst) {
            self.gate.pause();
        }
    }
}

async fn cancel_after_begin_acknowledgement(connection: &mut SqliteConnection) {
    let progress = Arc::new(Gate::default());
    let acknowledgement = Arc::new(Gate::default());
    let _release_progress = ReleaseOnDrop(progress.clone());
    let _release_acknowledgement = ReleaseOnDrop(acknowledgement.clone());
    let worker_progress = progress.clone();
    let mut paused = false;
    connection.lock_handle().await.expect("lock SQLite handle").set_progress_handler(
        1,
        move || {
            if paused {
                return true;
            }
            paused = true;
            worker_progress.pause()
        },
    );
    let waker = Waker::from(Arc::new(PausedWake {
        gate: acknowledgement.clone(),
        used: AtomicBool::new(false),
    }));
    let mut begin = connection.begin_with("BEGIN IMMEDIATE");
    assert!(begin.as_mut().poll(&mut Context::from_waker(&waker)).is_pending());
    progress.wait_for_entry();
    progress.release();
    acknowledgement.wait_for_entry();

    // The worker has published BEGIN's successful result but is still inside wake().
    // Polling consumes that ACK and must stop at custom-BEGIN's handle-lock validation.
    assert!(begin.as_mut().poll(&mut Context::from_waker(Waker::noop())).is_pending());
    drop(begin);
    assert!(connection.is_in_transaction(), "the acknowledged BEGIN has no Transaction guard");
    acknowledgement.release();
    connection.lock_handle().await.expect("remove progress hook").remove_progress_handler();
}

async fn fixture() -> (PathBuf, SqliteStore, Vec<PoolConnection<Sqlite>>) {
    let directory =
        std::env::temp_dir().join(format!("scoplen-sqlite-cancellation-{}", uuid::Uuid::new_v4()));
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("open store");
    let mut connections = Vec::new();
    for _ in 0..5 {
        connections.push(store.pool().acquire().await.expect("reserve pool connection"));
    }
    (directory, store, connections)
}

async fn assert_source_admission(store: &SqliteStore) {
    assert_eq!(
        tokio::time::timeout(
            DEADLINE,
            store.admit_device_auth_source(
                DeviceAuthEndpoint::Refresh,
                "192.0.2.9".parse().expect("test source")
            ),
        )
        .await
        .expect("writer reservation must be released")
        .expect("fresh source admission"),
        DeviceAuthAdmission::Admitted
    );
}

#[tokio::test]
async fn cancelled_custom_begin_returns_a_clean_connection_and_allows_admission() {
    let (directory, store, mut connections) = fixture().await;
    let mut connection = connections.pop().expect("controlled connection");
    sqlx::query("CREATE TEMP TABLE cancellation_connection (value INTEGER)")
        .execute(&mut *connection)
        .await
        .expect("connection identity");
    cancel_after_begin_acknowledgement(&mut connection).await;
    drop(connection);

    let mut reused = tokio::time::timeout(DEADLINE, store.pool().acquire())
        .await
        .expect("released connection returns")
        .expect("reacquire connection");
    assert!(
        !reused.is_in_transaction(),
        "cancelled BEGIN must not leak a transaction into the pool"
    );
    let identity: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_temp_master WHERE name='cancellation_connection'",
    )
    .fetch_one(&mut *reused)
    .await
    .expect("connection identity");
    assert_eq!(identity, 1, "successful rollback keeps the same connection usable");
    reused
        .begin_with("BEGIN IMMEDIATE")
        .await
        .expect("fresh immediate transaction")
        .commit()
        .await
        .expect("commit");
    drop(reused);
    drop(connections);
    assert_source_admission(&store).await;
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn queued_transaction_drop_rollback_does_not_reach_the_next_transaction() {
    let (directory, store, mut connections) = fixture().await;
    let mut connection = connections.pop().expect("controlled connection");
    sqlx::query("CREATE TEMP TABLE cancellation_values (value INTEGER)")
        .execute(&mut *connection)
        .await
        .expect("temporary probe");
    let mut transaction = connection.begin().await.expect("ordinary transaction");
    sqlx::query("INSERT INTO cancellation_values VALUES (1)")
        .execute(&mut *transaction)
        .await
        .expect("uncommitted value");
    drop(transaction);
    drop(connection);
    let mut reused = tokio::time::timeout(DEADLINE, store.pool().acquire())
        .await
        .expect("released connection returns")
        .expect("reacquire connection");
    assert!(!reused.is_in_transaction());
    let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM cancellation_values")
        .fetch_one(&mut *reused)
        .await
        .expect("rolled back values");
    assert_eq!(count, 0);
    let mut transaction = reused.begin_with("BEGIN IMMEDIATE").await.expect("new transaction");
    sqlx::query("INSERT INTO cancellation_values VALUES (2)")
        .execute(&mut *transaction)
        .await
        .expect("new value");
    transaction.commit().await.expect("new commit");
    let value: i64 = sqlx::query_scalar("SELECT value FROM cancellation_values")
        .fetch_one(&mut *reused)
        .await
        .expect("committed value");
    assert_eq!(value, 2);
    drop(reused);
    drop(connections);
    assert_source_admission(&store).await;
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}

#[tokio::test]
async fn failed_cancelled_begin_cleanup_discards_the_connection() {
    let (directory, store, mut connections) = fixture().await;
    let mut connection = connections.pop().expect("controlled connection");
    sqlx::query("CREATE TEMP TABLE discarded_connection (value INTEGER)")
        .execute(&mut *connection)
        .await
        .expect("connection identity");
    cancel_after_begin_acknowledgement(&mut connection).await;
    let interrupted = Arc::new(AtomicBool::new(false));
    let worker_interrupted = interrupted.clone();
    connection.lock_handle().await.expect("lock SQLite handle").set_progress_handler(
        1,
        move || {
            worker_interrupted.store(true, Ordering::SeqCst);
            false
        },
    );
    drop(connection);
    let mut replacement = tokio::time::timeout(DEADLINE, store.pool().acquire())
        .await
        .expect("failed cleanup releases pool slot")
        .expect("replacement connection");
    assert!(interrupted.load(Ordering::SeqCst), "cleanup attempted ROLLBACK");
    assert!(!replacement.is_in_transaction());
    let identity: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_temp_master WHERE name='discarded_connection'",
    )
    .fetch_one(&mut *replacement)
    .await
    .expect("replacement identity");
    assert_eq!(identity, 0, "an uncleanable connection must not return to the pool");
    drop(replacement);
    drop(connections);
    assert_source_admission(&store).await;
    store.pool().close().await;
    support::remove_test_directory(directory).await;
}
