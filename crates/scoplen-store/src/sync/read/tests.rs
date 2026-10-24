// SPDX-License-Identifier: AGPL-3.0-only

use super::{
    ChangePage, Metadata, ObjectId, RelationalStore, SqliteStore, SyncChange, SyncReadLimits,
    SyncStoreError, Uuid, VaultId, api, cbor_argument_bytes, page_bytes, select_page,
};
#[cfg(feature = "postgres-integration")]
use crate::PostgresStore;
use crate::sync::VaultKind;
use std::{collections::BTreeMap, sync::Mutex};

#[path = "../../../tests/support/mod.rs"]
mod support;

#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
struct Observation {
    queries: usize,
    rows: usize,
    bytes: usize,
}

static OBSERVATIONS: Mutex<BTreeMap<VaultId, Observation>> = Mutex::new(BTreeMap::new());

pub(super) fn payload_query(vault: VaultId) {
    if let Some(observation) = OBSERVATIONS.lock().expect("probe lock").get_mut(&vault) {
        observation.queries += 1;
    }
}

pub(super) fn payload_loaded(vault: VaultId, bytes: usize) {
    if let Some(observation) = OBSERVATIONS.lock().expect("probe lock").get_mut(&vault) {
        observation.rows += 1;
        observation.bytes += bytes;
    }
}

struct Probe(VaultId);

impl Probe {
    fn new(vault: VaultId) -> Self {
        OBSERVATIONS.lock().expect("probe lock").insert(vault, Observation::default());
        Self(vault)
    }
    fn take(&self) -> Observation {
        let mut all = OBSERVATIONS.lock().expect("probe lock");
        std::mem::take(all.get_mut(&self.0).expect("registered probe"))
    }
}

impl Drop for Probe {
    fn drop(&mut self) {
        OBSERVATIONS.lock().expect("probe lock").remove(&self.0);
    }
}

#[test]
fn metadata_cbor_sizes_match_public_codecs_at_header_boundaries() {
    let limits = SyncReadLimits { max_envelope_bytes: 266_241, max_body_bytes: usize::MAX };
    for count in [0_u32, 1, 21, 23, 24, 255, 256, 1_000] {
        for size in [0, 1, 23, 24, 255, 256, 65_535, 65_536, 266_241] {
            if count > 24 && size > 256 {
                continue;
            }
            for signed in [false, true] {
                let metadata = (0..count)
                    .map(|index| Metadata {
                        change: SyncChange {
                            object_id: Uuid::now_v7().into_bytes(),
                            sequence: u64::from(index) + 1,
                            envelope: Vec::new(),
                            key_epoch: 1,
                            tombstone: false,
                            signer_device_id: signed.then(|| Uuid::now_v7().into_bytes()),
                        },
                        bytes: size,
                    })
                    .collect::<Vec<_>>();
                let bytes = metadata
                    .iter()
                    .map(|entry| entry.encoded_bytes(limits).expect("entry size"))
                    .sum();
                let wire = metadata
                    .iter()
                    .map(|entry| {
                        let mut wire = entry.wire();
                        wire.payload = vec![1; size];
                        wire
                    })
                    .collect::<Vec<_>>();
                for cursor in
                    [u64::from(count), u64::from(u32::MAX), u64::from(u32::MAX) + 1, u64::MAX]
                {
                    let actual = api::SyncChangesResponse {
                        changes: wire.clone(),
                        next_cursor: cursor,
                        more: false,
                    }
                    .to_cbor_with_limits(limits)
                    .expect("public changes encoding");
                    assert_eq!(Some(actual.len()), page_bytes(bytes, metadata.len(), cursor));
                    let snapshot = api::SyncSnapshotResponse {
                        objects: wire.clone(),
                        next_cursor: cursor,
                        more: false,
                    }
                    .to_cbor_with_limits(limits)
                    .expect("public snapshot encoding");
                    assert_eq!(snapshot.len(), actual.len());
                }
                if (1..=21).contains(&count) {
                    let object = Uuid::now_v7();
                    let wire = wire
                        .into_iter()
                        .map(|mut entry| {
                            entry.object_id = object;
                            entry
                        })
                        .collect();
                    let actual = api::SyncVersionsResponse { versions: wire }
                        .to_cbor_with_limits(limits)
                        .expect("public history encoding");
                    assert_eq!(actual.len(), bytes + 10 + cbor_argument_bytes(u64::from(count)));
                }
            }
        }
    }
}

#[test]
fn metadata_selection_preserves_source_validation_and_cursor_boundaries() {
    let metadata = [23, 24, 256].map(|sequence| Metadata {
        change: SyncChange {
            object_id: Uuid::now_v7().into_bytes(),
            sequence,
            envelope: Vec::new(),
            key_epoch: 1,
            tombstone: false,
            signer_device_id: Some(Uuid::now_v7().into_bytes()),
        },
        bytes: 32,
    });
    let query = api::SyncChangesQuery { after: 0, limit: 1_000 };
    let exact_prefix = api::SyncChangesResponse {
        changes: metadata[..2]
            .iter()
            .map(|entry| {
                let mut wire = entry.wire();
                wire.payload = vec![1; entry.bytes];
                wire
            })
            .collect(),
        next_cursor: 24,
        more: true,
    }
    .to_cbor()
    .expect("public prefix encoding");
    let limits = SyncReadLimits { max_envelope_bytes: 32, max_body_bytes: exact_prefix.len() };
    for more in [false, true] {
        let selected = select_page(&metadata, query, i64::MAX as u64, more, Some(limits))
            .expect("exact longest prefix");
        assert_eq!((selected.count, selected.cursor, selected.more), (2, 24, true));
        let full =
            select_page(&metadata, query, i64::MAX as u64, more, Some(SyncReadLimits::default()))
                .expect("complete requested page");
        assert_eq!(full.count, 3);
        assert_eq!(full.cursor, if more { 256 } else { i64::MAX as u64 });
        assert_eq!(full.more, more);
    }
    for defect in 0..3 {
        let mut invalid = metadata
            .iter()
            .map(|entry| Metadata { change: entry.change.clone(), bytes: entry.bytes })
            .collect::<Vec<_>>();
        let mut current = 512;
        match defect {
            0 => invalid[2].change.object_id = invalid[0].change.object_id,
            1 => invalid[2].change.sequence = invalid[1].change.sequence,
            _ => current = 24,
        }
        assert!(matches!(
            select_page(&invalid, query, current, false, Some(limits)),
            Err(SyncStoreError::CorruptRow(_))
        ));
    }
    let query = api::SyncChangesQuery { after: i64::MAX as u64, limit: 1_000 };
    let empty_size = page_bytes(0, 0, query.after).expect("empty size");
    let selected = select_page(
        &[],
        query,
        query.after,
        false,
        Some(SyncReadLimits { max_body_bytes: empty_size, ..limits }),
    )
    .expect("exact empty final page");
    assert_eq!((selected.count, selected.cursor, selected.more), (0, query.after, false));
    assert!(matches!(
        select_page(
            &[],
            query,
            query.after,
            false,
            Some(SyncReadLimits { max_body_bytes: empty_size - 1, ..limits }),
        ),
        Err(SyncStoreError::ReadBudgetExceeded)
    ));
}

enum Backend {
    Sqlite(SqliteStore),
    #[cfg(feature = "postgres-integration")]
    Postgres(PostgresStore),
}

impl Backend {
    async fn page(
        &self,
        vault: VaultId,
        after: u64,
        snapshot: bool,
        limits: SyncReadLimits,
    ) -> Result<ChangePage, SyncStoreError> {
        if snapshot {
            let page = match self {
                Self::Sqlite(store) => {
                    store.sync_snapshot_with_read_limits(vault, after, 1_000, limits).await?
                }
                #[cfg(feature = "postgres-integration")]
                Self::Postgres(store) => {
                    store.sync_snapshot_with_read_limits(vault, after, 1_000, limits).await?
                }
            };
            Ok(ChangePage { changes: page.objects, next_cursor: page.next_cursor, more: page.more })
        } else {
            match self {
                Self::Sqlite(store) => {
                    store.sync_changes_with_read_limits(vault, after, 1_000, limits).await
                }
                #[cfg(feature = "postgres-integration")]
                Self::Postgres(store) => {
                    store.sync_changes_with_read_limits(vault, after, 1_000, limits).await
                }
            }
        }
    }

    async fn history(
        &self,
        vault: VaultId,
        object: ObjectId,
        limits: SyncReadLimits,
    ) -> Result<Vec<SyncChange>, SyncStoreError> {
        match self {
            Self::Sqlite(store) => {
                store.sync_versions_with_read_limits(vault, object, limits).await
            }
            #[cfg(feature = "postgres-integration")]
            Self::Postgres(store) => {
                store.sync_versions_with_read_limits(vault, object, limits).await
            }
        }
    }

    async fn signer(&self, vault: VaultId, object: ObjectId, signer: Option<Vec<u8>>) {
        match self {
            Self::Sqlite(store) => {
                sqlx::query("UPDATE sync_objects SET signer_device_id = ? WHERE vault_id = ? AND object_id = ?")
                    .bind(signer).bind(vault.as_slice()).bind(object.as_slice()).execute(store.pool()).await.expect("change test signer");
            }
            #[cfg(feature = "postgres-integration")]
            Self::Postgres(store) => {
                sqlx::query("UPDATE sync_objects SET signer_device_id = $1 WHERE vault_id = $2 AND object_id = $3")
                    .bind(signer).bind(vault.as_slice()).bind(object.as_slice()).execute(store.pool()).await.expect("change test signer");
            }
        }
    }
}

#[allow(clippy::too_many_lines)]
async fn exercise_admission(store: Backend, vault: VaultId, object: ObjectId) {
    let probe = Probe::new(vault);
    let limits = SyncReadLimits { max_envelope_bytes: 1_048_576, max_body_bytes: 160 };
    for snapshot in [false, true] {
        let page =
            store.page(vault, 0, snapshot, limits).await.expect("prefix before large object");
        assert_eq!(page.changes.iter().map(|entry| entry.sequence).collect::<Vec<_>>(), vec![1, 3]);
        assert!(page.more);
        assert_eq!(page.next_cursor, 3);
        assert_eq!(probe.take(), Observation { queries: 1, rows: 2, bytes: 14 });
        assert!(matches!(
            store.page(vault, 3, snapshot, limits).await,
            Err(SyncStoreError::ReadBudgetExceeded)
        ));
        assert_eq!(
            probe.take(),
            Observation::default(),
            "a first-entry rejection must precede the payload query"
        );
        assert!(matches!(
            store
                .page(vault, 0, snapshot, SyncReadLimits { max_envelope_bytes: 1, ..limits })
                .await,
            Err(SyncStoreError::ReadBudgetExceeded)
        ));
        assert_eq!(probe.take(), Observation::default());
        let full = store
            .page(vault, 0, snapshot, SyncReadLimits { max_body_bytes: 3_000_000, ..limits })
            .await
            .expect("full selected page");
        assert_eq!(full.changes.len(), 3);
        assert!(!full.more);
        assert_eq!(full.next_cursor, 4);
        assert_eq!(probe.take(), Observation { queries: 1, rows: 3, bytes: 1_048_590 });
        let empty = store.page(vault, 4, snapshot, limits).await.expect("empty final page");
        assert_eq!(empty.changes.len(), 0);
        assert_eq!(empty.next_cursor, 4);
        assert!(!empty.more);
        assert_eq!(probe.take(), Observation::default());
        assert!(matches!(
            store.page(vault, 4, snapshot, SyncReadLimits { max_body_bytes: 1, ..limits }).await,
            Err(SyncStoreError::ReadBudgetExceeded)
        ));
        assert_eq!(probe.take(), Observation::default());
        assert!(matches!(
            store.page(vault, 5, snapshot, limits).await,
            Err(SyncStoreError::CursorAhead { .. })
        ));
        assert_eq!(probe.take(), Observation::default());
        assert!(matches!(
            store
                .page(vault, 0, snapshot, SyncReadLimits { max_envelope_bytes: 0, ..limits })
                .await,
            Err(SyncStoreError::InvalidReadLimits)
        ));
        assert_eq!(probe.take(), Observation::default());
    }
    let one_version = SyncReadLimits { max_body_bytes: 1_048_776, ..limits };
    assert!(matches!(
        store.history(vault, object, one_version).await,
        Err(SyncStoreError::ReadBudgetExceeded)
    ));
    assert_eq!(
        probe.take(),
        Observation::default(),
        "history rejection must precede every payload query"
    );
    let history = store
        .history(vault, object, SyncReadLimits { max_body_bytes: 3_000_000, ..limits })
        .await
        .expect("complete history");
    assert_eq!(history.iter().map(|entry| entry.sequence).collect::<Vec<_>>(), vec![2, 4]);
    assert_eq!(probe.take(), Observation { queries: 1, rows: 2, bytes: 2_097_152 });
    store.signer(vault, object, Some(vec![1; 16])).await;
    for snapshot in [false, true] {
        assert!(matches!(
            store.page(vault, 0, snapshot, limits).await,
            Err(SyncStoreError::CorruptRow(_))
        ));
        assert_eq!(
            probe.take(),
            Observation::default(),
            "invalid omitted tail cannot be hidden by truncation"
        );
    }
    store.signer(vault, object, None).await;
}

#[tokio::test]
async fn sqlite_metadata_admission_precedes_blob_materialization() {
    let directory = std::env::temp_dir().join(format!("scoplen-read-admission-{}", Uuid::new_v4()));
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("test store");
    let vault = Uuid::now_v7().into_bytes();
    let object = Uuid::now_v7().into_bytes();
    store.create_sync_vault(vault, VaultKind::Personal).await.expect("vault");
    for sequence in [1_i64, 2, 3, 4] {
        let id = if sequence % 2 == 0 { object } else { Uuid::now_v7().into_bytes() };
        let size = if sequence % 2 == 0 { 1_048_576 } else { 7 };
        if sequence != 2 {
            sqlx::query("INSERT INTO sync_objects (vault_id, object_id, sequence, envelope, tombstone, key_epoch, written_at_ms) VALUES (?, ?, ?, zeroblob(?), 0, 1, 1)")
                .bind(vault.as_slice()).bind(id.as_slice()).bind(sequence).bind(size).execute(store.pool()).await.expect("server-generated blob");
        }
        if sequence % 2 == 0 {
            sqlx::query("INSERT INTO sync_object_versions (vault_id, object_id, sequence, envelope, tombstone, key_epoch, written_at_ms) VALUES (?, ?, ?, zeroblob(?), 0, 1, 1)")
                .bind(vault.as_slice()).bind(id.as_slice()).bind(sequence).bind(size).execute(store.pool()).await.expect("server-generated history blob");
        }
    }
    sqlx::query("UPDATE sync_vaults SET current_seq = 4 WHERE vault_id = ?")
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("current sequence");
    exercise_admission(Backend::Sqlite(store.clone()), vault, object).await;
    store.pool().close().await;
    drop(store);
    support::remove_test_directory(directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_metadata_admission_precedes_blob_materialization() {
    let url =
        std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("isolated PostgreSQL test database");
    let store = PostgresStore::connect(&url).await.expect("test store");
    let vault = Uuid::now_v7().into_bytes();
    let object = Uuid::now_v7().into_bytes();
    store.create_shared_sync_vault(vault, Uuid::now_v7().into_bytes(), &[1]).await.expect("vault");
    for sequence in [1_i64, 2, 3, 4] {
        let id = if sequence % 2 == 0 { object } else { Uuid::now_v7().into_bytes() };
        let size: i32 = if sequence % 2 == 0 { 1_048_576 } else { 7 };
        if sequence != 2 {
            sqlx::query("INSERT INTO sync_objects (vault_id, object_id, sequence, envelope, tombstone, key_epoch, written_at_ms) VALUES ($1, $2, $3, convert_to(repeat('x', $4), 'UTF8'), FALSE, 1, 1)")
                .bind(vault.as_slice()).bind(id.as_slice()).bind(sequence).bind(size).execute(store.pool()).await.expect("server-generated blob");
        }
        if sequence % 2 == 0 {
            sqlx::query("INSERT INTO sync_object_versions (vault_id, object_id, sequence, envelope, tombstone, key_epoch, written_at_ms) VALUES ($1, $2, $3, convert_to(repeat('x', $4), 'UTF8'), FALSE, 1, 1)")
                .bind(vault.as_slice()).bind(id.as_slice()).bind(sequence).bind(size).execute(store.pool()).await.expect("server-generated history blob");
        }
    }
    sqlx::query("UPDATE sync_vaults SET current_seq = 4 WHERE vault_id = $1")
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("current sequence");
    exercise_admission(Backend::Postgres(store.clone()), vault, object).await;
    sqlx::query("DELETE FROM sync_vaults WHERE vault_id = $1")
        .bind(vault.as_slice())
        .execute(store.pool())
        .await
        .expect("owned test vault cleanup");
    store.pool().close().await;
}
