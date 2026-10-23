// SPDX-License-Identifier: AGPL-3.0-only
//! Synchronization storage boundary and HTTP contract adapter.
//!
//! The HTTP adapter implements the K-4 CBOR request/response boundary over the selected durable
//! SQLite or PostgreSQL backend. Authentication remains an explicit trait boundary; the server
//! supplies the production enrolled-device JWT/DPoP and current Personal authorization adapter.

#![forbid(unsafe_code)]

pub use scoplen_store::sync::{
    ChangePage, ConflictEntry, DeviceId, MAX_BATCH_BYTES, MAX_BATCH_OBJECTS, MAX_ENVELOPE_BYTES,
    MAX_PAGE_SIZE, ObjectId, ObjectWrite, SnapshotPage, SyncChange, SyncStoreError, VaultId,
    VaultKind, WriteReceipt,
};

pub mod http;
pub mod notify;

/// Sync contract marker.
pub const COMPONENT: &str = "sync";
