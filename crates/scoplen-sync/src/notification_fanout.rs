// SPDX-License-Identifier: AGPL-3.0-only
//! Owned PostgreSQL listener and bounded, currently authorized per-instance delivery.

use std::{sync::Arc, time::Duration};

use scoplen_api::sync::SyncNotification;
use scoplen_store::{
    PostgresStore, RelationalStore,
    sync::SyncStoreError,
    sync_notifications::{SyncNotificationListener, SyncNotificationMessage},
};
use tokio::{
    sync::mpsc,
    time::{Instant, timeout, timeout_at},
};

use crate::{
    http::{SyncAuthenticator, SyncOperation},
    notify::NotificationHub,
};

const QUEUE_CAPACITY: usize = 64;
const DATABASE_TIMEOUT: Duration = Duration::from_secs(5);
const INITIAL_RETRY: Duration = Duration::from_millis(100);
const MAX_RETRY: Duration = Duration::from_secs(5);

/// Prepare before accepting sockets, then run as a future owned by the API listener.
/// Dropping the owner interrupts sockets and releases its dedicated pool connection.
pub struct PostgresNotificationFanout<A> {
    store: Arc<PostgresStore>,
    listener: Option<SyncNotificationListener>,
    authenticator: A,
    hub: NotificationHub,
}

impl<A: SyncAuthenticator> PostgresNotificationFanout<A> {
    /// Establish LISTEN before the HTTP listener can acknowledge notification sockets.
    ///
    /// # Errors
    /// Returns a storage error or timeout without claiming that notifications are available.
    pub async fn connect(
        store: Arc<PostgresStore>,
        authenticator: A,
        hub: NotificationHub,
    ) -> Result<Self, SyncStoreError> {
        hub.unavailable();
        let listener = timeout(DATABASE_TIMEOUT, store.listen_sync_notifications())
            .await
            .map_err(|_| SyncStoreError::CorruptRow("notification subscription timeout"))??;
        hub.available();
        Ok(Self { store, listener: Some(listener), authenticator, hub })
    }

    /// Run receipt and authorization concurrently, without detached application tasks.
    /// A slow recipient or database cannot block committed HTTP writes or grow this queue.
    ///
    /// # Errors
    /// Returns when the owning database pool closes or the listener cannot continue.
    pub async fn run(mut self) -> Result<(), SyncStoreError> {
        let (send, receive) = mpsc::channel(QUEUE_CAPACITY);
        let listener = self
            .listener
            .take()
            .ok_or(SyncStoreError::CorruptRow("notification listener unavailable"))?;
        let reader = read(self.store.clone(), listener, self.hub.clone(), send);
        let dispatcher = dispatch(&self.authenticator, &self.hub, receive);
        tokio::select! {
            result = reader => result,
            () = dispatcher => Ok(()),
        }
    }
}

impl<A> Drop for PostgresNotificationFanout<A> {
    fn drop(&mut self) {
        self.hub.unavailable();
    }
}

async fn read(
    store: Arc<PostgresStore>,
    mut listener: SyncNotificationListener,
    hub: NotificationHub,
    send: mpsc::Sender<SyncNotification>,
) -> Result<(), SyncStoreError> {
    loop {
        match listener.recv().await {
            Ok(SyncNotificationMessage::Event(event)) => {
                enqueue(&send, &hub, event);
            }
            Ok(SyncNotificationMessage::Invalid) => {
                tracing::warn!("invalid internal sync notification ignored");
            }
            interrupted => {
                hub.unavailable();
                tracing::warn!("sync notification listener interrupted; reconnecting");
                if store.pool().is_closed() {
                    return interrupted.map(|_| ());
                }
                drop(listener);
                let mut retry = INITIAL_RETRY;
                loop {
                    tokio::time::sleep(retry).await;
                    match timeout(DATABASE_TIMEOUT, store.listen_sync_notifications()).await {
                        Ok(Ok(value)) => {
                            listener = value;
                            break;
                        }
                        Ok(Err(error)) if store.pool().is_closed() => return Err(error),
                        _ => retry = (retry * 2).min(MAX_RETRY),
                    }
                }
                hub.available();
                tracing::info!("sync notification listener restored");
            }
        }
    }
}

pub(crate) fn enqueue(
    send: &mpsc::Sender<SyncNotification>,
    hub: &NotificationHub,
    event: SyncNotification,
) {
    if send.try_send(event).is_err() {
        hub.interrupt();
        tracing::warn!("sync notification queue overflow; sockets must reconcile");
    }
}

pub(crate) async fn dispatch<A: SyncAuthenticator>(
    authenticator: &A,
    hub: &NotificationHub,
    mut receive: mpsc::Receiver<SyncNotification>,
) {
    while let Some(event) = receive.recv().await {
        let vault = match &event {
            SyncNotification::VaultAdvanced { vault, .. }
            | SyncNotification::RotationPending { vault } => *vault.as_bytes(),
            SyncNotification::DeviceRevoked => continue,
        };
        for recipient in hub.active_devices() {
            let deadline = Instant::now() + DATABASE_TIMEOUT;
            let permitted = timeout_at(deadline, async {
                authenticator.authorize_notifications(recipient).await?;
                authenticator.authorize(recipient, vault, SyncOperation::Read).await
            })
            .await;
            let permitted = if Instant::now() >= deadline { None } else { Some(permitted) };
            match permitted {
                Some(Ok(Ok(()))) => {
                    let _ = hub.publish(recipient, &event);
                }
                Some(Ok(Err(error))) if !error.status.is_server_error() => {}
                _ => {
                    hub.interrupt();
                    tracing::warn!(
                        "sync notification authorization unavailable; sockets must reconcile"
                    );
                    break;
                }
            }
        }
    }
}
