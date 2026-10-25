// SPDX-License-Identifier: AGPL-3.0-only

mod support;

#[path = "support/pool_close.rs"]
mod pool_close;

use std::{
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};

use sqlx::{
    SqlitePool,
    sqlite::{SqliteConnectOptions, SqlitePoolOptions},
};
use tokio::sync::Notify;

fn controlled_pool(
    path: &Path,
    max_connections: u32,
    pause: Arc<AtomicBool>,
    entered: Arc<Notify>,
    resume: Arc<Notify>,
) -> SqlitePool {
    SqlitePoolOptions::new()
        .max_connections(max_connections)
        .min_connections(0)
        .idle_timeout(None)
        .max_lifetime(None)
        .after_release(move |_, _| {
            let pause = pause.clone();
            let entered = entered.clone();
            let resume = resume.clone();
            Box::pin(async move {
                if pause.load(Ordering::SeqCst) {
                    entered.notify_one();
                    resume.notified().await;
                }
                Ok(true)
            })
        })
        .connect_lazy_with(SqliteConnectOptions::new().filename(path).create_if_missing(true))
}

#[tokio::test]
async fn already_removed_directory_is_clean() {
    let path = std::env::temp_dir().join(format!("scoplen-cleanup-{}", uuid::Uuid::new_v4()));
    support::remove_test_directory(path).await;
}

#[tokio::test]
async fn sqlite_fixture_close_waits_for_a_return_already_inside_after_release() {
    let path = std::env::temp_dir().join(format!("scoplen-cleanup-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("isolated fixture");
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let pool = controlled_pool(
        &path.join("scoplen.sqlite"),
        1,
        Arc::new(AtomicBool::new(true)),
        entered.clone(),
        resume.clone(),
    );
    let connection = pool.acquire().await.expect("controlled connection");
    drop(connection);
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .expect("connection return reached after_release");

    let closing = pool_close::close(&pool);
    tokio::pin!(closing);
    let waited_for_return = futures_util::poll!(closing.as_mut()).is_pending();
    resume.notify_one();
    tokio::time::timeout(Duration::from_secs(5), closing)
        .await
        .expect("pool close completes after releasing the callback");
    assert_eq!(pool.size(), 0, "fixture close drains the late idle connection");
    support::remove_test_directory(path).await;
    assert!(waited_for_return, "pool close must wait for the held connection permit");
}

#[tokio::test]
async fn fixture_closes_wait_for_a_return_when_another_connection_was_idle() {
    let path = std::env::temp_dir().join(format!("scoplen-cleanup-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("isolated fixture");
    let pause = Arc::new(AtomicBool::new(false));
    let entered = Arc::new(Notify::new());
    let resume = Arc::new(Notify::new());
    let pool = controlled_pool(
        &path.join("scoplen.sqlite"),
        2,
        pause.clone(),
        entered.clone(),
        resume.clone(),
    );
    let idle = pool.acquire().await.expect("future idle connection");
    let returning = pool.acquire().await.expect("controlled returning connection");
    drop(idle);
    tokio::time::timeout(Duration::from_secs(5), async {
        while pool.num_idle() != 1 {
            tokio::task::yield_now().await;
        }
    })
    .await
    .expect("one connection became idle");
    pause.store(true, Ordering::SeqCst);
    drop(returning);
    tokio::time::timeout(Duration::from_secs(5), entered.notified())
        .await
        .expect("other connection reached after_release");

    let first_close = pool_close::close(&pool);
    tokio::pin!(first_close);
    let first_pending = tokio::time::timeout(Duration::from_secs(5), async {
        tokio::select! {
            biased;
            () = first_close.as_mut() => false,
            () = async {
                while pool.size() != 1 {
                    tokio::task::yield_now().await;
                }
            } => true,
        }
    })
    .await
    .expect("idle connection closes while the returning connection remains gated");
    let second_close = pool_close::close(&pool);
    tokio::pin!(second_close);
    let second_pending = futures_util::poll!(second_close.as_mut()).is_pending();
    let remaining_before_release = pool.size();
    resume.notify_one();
    if first_pending {
        tokio::time::timeout(Duration::from_secs(5), first_close)
            .await
            .expect("first pool close finishes");
    }
    if second_pending {
        tokio::time::timeout(Duration::from_secs(5), second_close)
            .await
            .expect("second pool close finishes");
    }

    assert_eq!(pool.size(), 0, "fixture closes drain every connection");
    support::remove_test_directory(path).await;
    assert!(
        first_pending && second_pending,
        "close returned before callback release: first_pending={first_pending}, second_pending={second_pending}, live={remaining_before_release}"
    );
}

#[cfg(windows)]
#[tokio::test]
async fn cleanup_waits_for_a_real_windows_sharing_lock_beyond_one_second() {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt};

    let path = std::env::temp_dir().join(format!("scoplen-cleanup-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&path).expect("isolated fixture");
    let locked = OpenOptions::new()
        .write(true)
        .create_new(true)
        .share_mode(0)
        .open(path.join("scoplen.sqlite"))
        .expect("hold a non-delete-sharing handle");
    let error = std::fs::remove_dir_all(&path).expect_err("held file must block cleanup");
    assert_eq!(error.raw_os_error(), Some(32));

    let release = async move {
        tokio::time::sleep(Duration::from_millis(1_500)).await;
        drop(locked);
    };
    tokio::join!(support::remove_test_directory(path.clone()), release);
    assert!(!path.exists(), "cleanup must finish after the handle is released");
}
