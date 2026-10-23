// SPDX-License-Identifier: AGPL-3.0-only
//! Local fan-out for content-free K-4 sync notifications.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use scoplen_api::sync::SyncNotification;
use tokio::sync::{broadcast, watch};

use crate::http::AuthenticatedDevice;

const CHANNEL_CAPACITY: usize = 64;

/// Per-process notification fan-out keyed by authenticated device.
///
/// Publishing is deliberately separate from authentication and policy. The service publishes an
/// event only after it has committed a change and selected the devices that may receive it. A
/// multi-instance deployment feeds this API from PostgreSQL `LISTEN`/`NOTIFY`.
#[derive(Clone, Debug)]
pub struct NotificationHub {
    channels: Arc<Mutex<HashMap<AuthenticatedDevice, broadcast::Sender<Vec<u8>>>>>,
    lifecycle: watch::Sender<NotificationLifecycle>,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct NotificationLifecycle {
    pub available: bool,
    pub generation: u64,
}

impl Default for NotificationHub {
    fn default() -> Self {
        Self {
            channels: Arc::default(),
            lifecycle: watch::channel(NotificationLifecycle { available: true, generation: 0 }).0,
        }
    }
}

impl NotificationHub {
    /// Close current sockets after a listener gap, overflow, or worker shutdown.
    pub fn unavailable(&self) {
        self.lifecycle.send_modify(|state| {
            state.available = false;
            state.generation = state.generation.wrapping_add(1);
        });
    }

    /// Fence current sockets without changing the listener's current availability.
    pub(crate) fn interrupt(&self) {
        self.lifecycle.send_modify(|state| state.generation = state.generation.wrapping_add(1));
    }

    /// Allow new sockets after LISTEN has completed successfully.
    pub fn available(&self) {
        self.lifecycle.send_modify(|state| state.available = true);
    }

    /// Whether a new socket can rely on this instance's notification source.
    #[must_use]
    pub fn is_available(&self) -> bool {
        self.lifecycle.borrow().available
    }

    pub(crate) fn lifecycle(&self) -> watch::Receiver<NotificationLifecycle> {
        self.lifecycle.subscribe()
    }

    /// Subscribe one device to content-free event bytes.
    #[must_use]
    pub fn subscribe(&self, identity: AuthenticatedDevice) -> broadcast::Receiver<Vec<u8>> {
        let mut channels = self.channels.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        channels
            .entry(identity)
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe()
    }

    /// Return the number of active WebSocket receivers for one device.
    pub fn receiver_count(&self, identity: AuthenticatedDevice) -> usize {
        self.channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&identity)
            .map_or(0, broadcast::Sender::receiver_count)
    }

    /// List connected devices for authorization before local publication.
    pub(crate) fn active_devices(&self) -> Vec<AuthenticatedDevice> {
        let mut channels = self.channels.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        channels.retain(|_, sender| sender.receiver_count() > 0);
        channels.keys().copied().collect()
    }

    /// Encode and publish one event to all current connections for a device.
    ///
    /// The return value is the number of receivers that accepted the event. Publishing to a
    /// device with no active connections is a successful no-op.
    ///
    /// # Errors
    ///
    /// Returns the protocol codec error when the event cannot be encoded canonically.
    pub fn publish(
        &self,
        identity: AuthenticatedDevice,
        event: &SyncNotification,
    ) -> Result<usize, scoplen_api::sync::SyncCodecError> {
        let payload = event.to_cbor()?;
        let sender = self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&identity)
            .cloned();
        Ok(sender.map_or(0, |sender| sender.send(payload).unwrap_or(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    fn identity(device_id: [u8; 16]) -> AuthenticatedDevice {
        AuthenticatedDevice { device_id, account_id: [4; 16] }
    }

    #[tokio::test]
    async fn publishes_only_to_the_target_device() {
        let hub = NotificationHub::default();
        let first_device = identity([1; 16]);
        let second_device = identity([2; 16]);
        let mut first = hub.subscribe(first_device);
        let mut second = hub.subscribe(second_device);
        let event = SyncNotification::VaultAdvanced { vault: Uuid::now_v7(), seq: 4 };

        assert_eq!(hub.publish(first_device, &event).expect("event encodes"), 1);
        assert_eq!(
            SyncNotification::from_cbor(&first.recv().await.expect("target event")),
            Ok(event)
        );
        assert!(matches!(second.try_recv(), Err(broadcast::error::TryRecvError::Empty)));
    }

    #[test]
    fn publishing_without_a_connection_is_a_noop() {
        let hub = NotificationHub::default();
        let event = SyncNotification::DeviceRevoked;
        assert_eq!(hub.publish(identity([3; 16]), &event).expect("event encodes"), 0);
    }

    #[test]
    fn active_devices_excludes_closed_connections() {
        let hub = NotificationHub::default();
        let first_device = identity([1; 16]);
        let second_device = identity([2; 16]);
        let first = hub.subscribe(first_device);
        let _second = hub.subscribe(second_device);
        drop(first);

        assert_eq!(hub.active_devices(), vec![second_device]);
        assert_eq!(hub.receiver_count(first_device), 0);
    }

    #[tokio::test]
    async fn isolates_different_accounts_with_the_same_device_id() {
        let hub = NotificationHub::default();
        let first = identity([1; 16]);
        let other = AuthenticatedDevice { account_id: [5; 16], ..first };
        let mut first_events = hub.subscribe(first);
        let mut other_events = hub.subscribe(other);
        let event = SyncNotification::DeviceRevoked;

        assert_eq!(hub.publish(first, &event).expect("event encodes"), 1);
        assert_eq!(
            SyncNotification::from_cbor(&first_events.recv().await.expect("first event")),
            Ok(event)
        );
        assert!(matches!(other_events.try_recv(), Err(broadcast::error::TryRecvError::Empty)));
        let active = hub.active_devices();
        assert_eq!(active.len(), 2);
        assert!(active.contains(&first));
        assert!(active.contains(&other));
    }
}
