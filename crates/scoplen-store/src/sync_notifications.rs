// SPDX-License-Identifier: AGPL-3.0-only
//! Transactional, content-free PostgreSQL sync hints.

use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use scoplen_api::sync::SyncNotification;
use sqlx::{Postgres, Transaction, postgres::PgListener};

use crate::{PostgresStore, RelationalStore, sync::SyncStoreError};

const MAX_PAYLOAD_BYTES: usize = 128;
// PostgreSQL channels are database-wide. Separate schemas, including isolated integration
// fixtures, must not consume each other's hints. The hash only bounds the identifier length.
const CHANNEL_SQL: &str = "SELECT 'scoplen_sync_v1_' || md5(current_schema())";

/// One observation from the dedicated PostgreSQL listener.
pub enum SyncNotificationMessage {
    /// A bounded, canonical vault hint; authorization is still the service's responsibility.
    Event(SyncNotification),
    /// The connection was lost, so some hints may be missing.
    Interrupted,
    /// An invalid internal payload was ignored without logging its contents.
    Invalid,
}

/// An owned LISTEN connection. Dropping it returns the connection to its pool.
pub struct SyncNotificationListener {
    inner: PgListener,
}

impl PostgresStore {
    /// Subscribe before accepting sockets. Uses one connection from the existing pool.
    ///
    /// # Errors
    /// Returns an error when the database cannot establish the subscription.
    pub async fn listen_sync_notifications(
        &self,
    ) -> Result<SyncNotificationListener, SyncStoreError> {
        let channel: String = sqlx::query_scalar(CHANNEL_SQL).fetch_one(self.pool()).await?;
        let mut inner = PgListener::connect_with(self.pool()).await?;
        inner.eager_reconnect(false);
        inner.listen(&channel).await?;
        Ok(SyncNotificationListener { inner })
    }
}

impl SyncNotificationListener {
    /// Receive without hiding a lost connection. After interruption, create a fresh listener
    /// before announcing recovery; notifications are not a durable delivery queue.
    ///
    /// # Errors
    /// Returns an error on database failure or when the owning pool closes.
    pub async fn recv(&mut self) -> Result<SyncNotificationMessage, SyncStoreError> {
        let Some(message) = self.inner.try_recv().await? else {
            return Ok(SyncNotificationMessage::Interrupted);
        };
        Ok(decode(message.payload())
            .map_or(SyncNotificationMessage::Invalid, SyncNotificationMessage::Event))
    }
}

pub(crate) async fn publish(
    transaction: &mut Transaction<'_, Postgres>,
    event: &SyncNotification,
) -> Result<(), SyncStoreError> {
    let payload = URL_SAFE_NO_PAD
        .encode(event.to_cbor().map_err(|_| SyncStoreError::CorruptRow("sync notification"))?);
    sqlx::query("SELECT pg_notify('scoplen_sync_v1_' || md5(current_schema()), $1)")
        .bind(payload)
        .execute(&mut **transaction)
        .await?;
    Ok(())
}

fn decode(payload: &str) -> Option<SyncNotification> {
    if payload.len() > MAX_PAYLOAD_BYTES {
        return None;
    }
    let bytes = URL_SAFE_NO_PAD.decode(payload).ok()?;
    let event = SyncNotification::from_cbor(&bytes).ok()?;
    match event {
        SyncNotification::VaultAdvanced { seq, .. } if seq > 0 && i64::try_from(seq).is_ok() => {
            Some(event)
        }
        SyncNotification::RotationPending { .. } => Some(event),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use uuid::Uuid;

    #[test]
    fn internal_payload_accepts_only_bounded_canonical_vault_hints() {
        let vault = Uuid::now_v7();
        for event in [
            SyncNotification::VaultAdvanced { vault, seq: 1 },
            SyncNotification::RotationPending { vault },
        ] {
            let payload = URL_SAFE_NO_PAD.encode(event.to_cbor().expect("canonical event"));
            assert_eq!(decode(&payload), Some(event));
        }
        for event in [
            SyncNotification::DeviceRevoked,
            SyncNotification::VaultAdvanced { vault, seq: u64::MAX },
        ] {
            let payload = URL_SAFE_NO_PAD.encode(event.to_cbor().expect("canonical event"));
            assert_eq!(decode(&payload), None);
        }
        assert_eq!(decode(&"x".repeat(MAX_PAYLOAD_BYTES + 1)), None);
        assert_eq!(decode("invalid!"), None);
        assert_eq!(decode("oA"), None);
    }
}
