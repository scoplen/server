// SPDX-License-Identifier: AGPL-3.0-only
//! Local fan-out for content-free K-4 sync notifications.

#![forbid(unsafe_code)]

use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};

use scoplen_api::sync::SyncNotification;
use scoplen_store::sync::DeviceId;
use tokio::sync::broadcast;

const CHANNEL_CAPACITY: usize = 64;

/// Per-process notification fan-out keyed by authenticated device.
///
/// Publishing is deliberately separate from authentication and policy. The service publishes an
/// event only after it has committed a change and selected the devices that may receive it. A
/// future multi-instance implementation can keep this API and feed it from PostgreSQL
/// `LISTEN`/`NOTIFY`.
#[derive(Clone, Debug, Default)]
pub struct NotificationHub {
    channels: Arc<Mutex<HashMap<DeviceId, broadcast::Sender<Vec<u8>>>>>,
}

impl NotificationHub {
    /// Subscribe one device to content-free event bytes.
    #[must_use]
    pub fn subscribe(&self, device_id: DeviceId) -> broadcast::Receiver<Vec<u8>> {
        let mut channels = self.channels.lock().unwrap_or_else(std::sync::PoisonError::into_inner);
        channels
            .entry(device_id)
            .or_insert_with(|| broadcast::channel(CHANNEL_CAPACITY).0)
            .subscribe()
    }

    /// Return the number of active WebSocket receivers for one device.
    pub fn receiver_count(&self, device_id: DeviceId) -> usize {
        self.channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&device_id)
            .map_or(0, broadcast::Sender::receiver_count)
    }

    /// List connected devices for authorization before local publication.
    pub(crate) fn active_devices(&self) -> Vec<DeviceId> {
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
        device_id: DeviceId,
        event: &SyncNotification,
    ) -> Result<usize, scoplen_api::sync::SyncCodecError> {
        let payload = event.to_cbor()?;
        let sender = self
            .channels
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&device_id)
            .cloned();
        Ok(sender.map_or(0, |sender| sender.send(payload).unwrap_or(0)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[tokio::test]
    async fn publishes_only_to_the_target_device() {
        let hub = NotificationHub::default();
        let first_device = [1; 16];
        let second_device = [2; 16];
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
        assert_eq!(hub.publish([3; 16], &event).expect("event encodes"), 0);
    }

    #[test]
    fn active_devices_excludes_closed_connections() {
        let hub = NotificationHub::default();
        let first_device = [1; 16];
        let second_device = [2; 16];
        let first = hub.subscribe(first_device);
        let _second = hub.subscribe(second_device);
        drop(first);

        assert_eq!(hub.active_devices(), vec![second_device]);
        assert_eq!(hub.receiver_count(first_device), 0);
    }
}
