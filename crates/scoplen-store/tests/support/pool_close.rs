// SPDX-License-Identifier: AGPL-3.0-only

use std::time::Duration;

pub async fn close<DB: sqlx::Database>(pool: &sqlx::Pool<DB>) {
    let drained = tokio::time::timeout(Duration::from_secs(10), async {
        loop {
            pool.close().await;
            if pool.size() == 0 {
                return;
            }
            // SQLx 0.8.6 may return from close before an in-flight return reaches idle.
            // Let that return finish, then drain again until the live count reaches zero.
            tokio::task::yield_now().await;
        }
    })
    .await;
    assert!(
        drained.is_ok(),
        "pool close did not drain all connections: live={}, idle={}",
        pool.size(),
        pool.num_idle()
    );
}
