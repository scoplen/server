// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_api::sync::SyncSnapshotResponse;
use scoplen_model::Tombstone;

async fn worker(f: &Fixture) {
    let now =
        i64::try_from(SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_millis())
            .expect("worker timestamp");
    let (_, processed) = match &f.backend {
        AuthBackend::Sqlite(store) => {
            crate::runtime::worker_retention_pass_at(store.as_ref(), now).await
        }
        AuthBackend::Postgres(store) => {
            crate::runtime::worker_retention_pass_at(store.as_ref(), now).await
        }
    }
    .expect("real worker pass");
    assert_eq!(processed, 1);
}

async fn retention_flow(mut f: Fixture) {
    let PersonalBootstrap { receipt, token, client, .. } = bootstrap_personal(&mut f).await;
    sync_object(&f, &receipt, &token, &client).await;
    let vault = receipt.personal_vault_id;
    let changes_path = format!("/sync/v1/vaults/{vault}/changes?after=0&limit=10");
    let reply = protected(&f, "GET", &changes_path, &[], &token, &client).await;
    assert_eq!(reply.status, 200);
    let changes = SyncChangesResponse::from_cbor(&reply.body).expect("original signed host");
    let change = &changes.changes[0];
    let vault_key = SecretBytes::new([8; 32]);
    let mut object = ObjectEnvelope::decode(&change.payload)
        .expect("envelope")
        .decrypt(vault, change.object_id, &vault_key, &client.public_key_sec1())
        .expect("verify before deleting");
    object.set_tombstone(Some(
        Tombstone::new(Hlc::at(2).expect("clock"), receipt.device_id).expect("tombstone"),
    ));
    let payload =
        ObjectEnvelope::encrypt(vault, 1, &object, &vault_key, receipt.device_id, &client)
            .expect("signed encrypted tombstone")
            .encode()
            .expect("envelope");
    let body = SyncWriteBatch {
        writes: vec![SyncWrite {
            object_id: change.object_id,
            base_seq: Some(1),
            payload,
            tombstone: true,
        }],
    }
    .to_cbor()
    .expect("delete batch");
    let reply =
        protected(&f, "POST", &format!("/sync/v1/vaults/{vault}/objects"), &body, &token, &client)
            .await;
    assert_eq!(reply.status, 200);
    assert_eq!(
        SyncWriteBatchResponse::from_cbor(&reply.body).expect("delete receipt").assignments[0].seq,
        2
    );
    worker(&f).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_objects").await, 1);
    assert_eq!(f.count("SELECT purge_horizon FROM sync_vaults").await, 0);
    let reply = protected(
        &f,
        "POST",
        &format!("/sync/v1/vaults/{vault}/ack"),
        &SyncAckRequest { cursor: 2 }.to_cbor().expect("ACK"),
        &token,
        &client,
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(SyncAckResponse::from_cbor(&reply.body).expect("durable ACK").cursor, 2);
    worker(&f).await;
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_objects").await, 0);
    assert_eq!(f.count("SELECT COUNT(*) FROM sync_object_versions").await, 0);
    assert_eq!(f.count("SELECT purge_horizon FROM sync_vaults").await, 2);
    let reply = protected(&f, "GET", &changes_path, &[], &token, &client).await;
    assert_eq!(reply.status, 410);
    let reply = protected(
        &f,
        "GET",
        &format!("/sync/v1/vaults/{vault}/snapshot?after=0&limit=10"),
        &[],
        &token,
        &client,
    )
    .await;
    assert_eq!(reply.status, 200);
    assert_eq!(SyncSnapshotResponse::from_cbor(&reply.body).expect("reconciliation").objects, []);
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_public_ack_enables_worker_tombstone_purge_and_snapshot_reconciliation() {
    retention_flow(Fixture::sqlite().await).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_public_ack_enables_worker_tombstone_purge_and_snapshot_reconciliation() {
    retention_flow(Fixture::postgres().await).await;
}
