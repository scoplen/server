// SPDX-License-Identifier: AGPL-3.0-only

mod support;

#[tokio::test]
async fn already_removed_directory_is_clean() {
    let path = std::env::temp_dir().join(format!("scoplen-cleanup-{}", uuid::Uuid::new_v4()));
    support::remove_test_directory(path).await;
}

#[cfg(windows)]
#[tokio::test]
async fn cleanup_waits_for_a_real_windows_sharing_lock_beyond_one_second() {
    use std::{fs::OpenOptions, os::windows::fs::OpenOptionsExt, time::Duration};

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
