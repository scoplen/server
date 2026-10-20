// SPDX-License-Identifier: AGPL-3.0-only

use std::{io, path::PathBuf, time::Duration};

pub async fn remove_test_directory(path: PathBuf) {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(10);
    loop {
        match std::fs::remove_dir_all(&path) {
            Ok(()) => return,
            Err(error) if error.kind() == io::ErrorKind::NotFound => return,
            // Closing SQLx waits for its SQLite worker; Windows scanners can still hold
            // a non-delete-sharing handle after that acknowledgement. Retry only those locks.
            Err(error)
                if cfg!(windows)
                    && matches!(error.raw_os_error(), Some(32 | 33))
                    && tokio::time::Instant::now() < deadline =>
            {
                tokio::time::sleep(Duration::from_millis(50)).await;
            }
            Err(error) => panic!("remove test directory {}: {error}", path.display()),
        }
    }
}
