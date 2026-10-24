// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use scoplen_api::sync::{SyncConflictProblem, SyncReadLimits};

fn limits() -> WriteBodyLimits {
    WriteBodyLimits::new(266_241, 501, 4_800_000).expect("raised deployment limits")
}

fn write_headers<'a>(authorization: &'a str, proof: &'a str) -> [(&'static str, &'a str); 3] {
    [("Content-Type", "application/cbor"), ("Authorization", authorization), ("DPoP", proof)]
}

fn signed_opaque_write(vault: Uuid, device: Uuid, object: Uuid, size: usize) -> SyncWrite {
    // Exercise server-side opaque-signature admission independently of K-1 plaintext limits.
    let mut write = signed_write(vault, device, object);
    let mut envelope = ObjectEnvelope::decode(&write.payload).expect("envelope");
    envelope.ciphertext.resize(size - (1 + 4 + 24 + 16 + 64), 0x51);
    let aad = cbor::encode(&cbor::Value::Array(vec![
        cbor::Value::Bytes(vault.as_bytes().to_vec()),
        cbor::Value::Bytes(object.as_bytes().to_vec()),
        cbor::Value::UInt(1),
        cbor::Value::Text("spl-object-v1".into()),
    ]))
    .expect("documented K-2 AAD");
    let mut input = envelope.encode().expect("envelope");
    input.truncate(input.len() - 64);
    input.extend_from_slice(&aad);
    envelope.signature = device_key().sign(&input);
    envelope
        .verify_signature(vault, object, &device_key().public_key_sec1())
        .expect("real device signature");
    write.payload = envelope.encode().expect("signed opaque envelope");
    assert_eq!(write.payload.len(), size);
    write
}

#[allow(clippy::too_many_lines)]
async fn exercise_listener(
    database: ListenerDatabase,
    directory: &std::path::Path,
    device: Uuid,
    vault: Uuid,
) {
    let object_storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
        root: directory.join("objects"),
    })
    .expect("object storage");
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let app = api_router_with_limits(
        database,
        Arc::new(object_storage),
        kms(directory),
        ORIGIN.into(),
        true,
        WriteRateLimits::default(),
        limits(),
        ReadBodyLimits::new(266_241, 1_000_000).expect("selected read budgets"),
    );
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("serve production authentication router");
    });
    let token = issue_token(address, device).await;
    let authorization = format!("DPoP {token}");
    let object = Uuid::now_v7();
    let write = signed_opaque_write(vault, device, object, 266_241);
    let batch = SyncWriteBatch { writes: vec![write.clone()] };
    let body = batch.to_cbor_with_limits(limits().codec_limits()).expect("raised batch");
    let objects_path = format!("/sync/v1/vaults/{vault}/objects");
    let write_proof = proof("POST", &objects_path, &token);
    let result =
        http(address, "POST", &objects_path, &body, &write_headers(&authorization, &write_proof))
            .await;
    assert_eq!(result.status, 200, "large certified write");
    let response =
        SyncWriteBatchResponse::from_cbor_with_limits(&result.body, limits().codec_limits())
            .expect("assignments");
    response
        .validate_for_batch_with_limits(&batch, limits().codec_limits())
        .expect("request binding");
    assert_eq!(response.assignments[0].seq, 1);

    let write_proof = proof("POST", &objects_path, &token);
    let conflict =
        http(address, "POST", &objects_path, &body, &write_headers(&authorization, &write_proof))
            .await;
    assert_eq!(conflict.status, 409);
    let conflict =
        SyncConflictProblem::from_cbor_with_limits(&conflict.body, limits().codec_limits())
            .expect("large current conflict");
    conflict
        .validate_for_batch_with_limits(&batch, limits().codec_limits())
        .expect("bound conflict");
    assert_eq!(conflict.conflicts[0].current.as_ref().expect("current").payload, write.payload);

    let reads = SyncReadLimits { max_envelope_bytes: 266_241, max_body_bytes: 1_000_000 };
    let changes_path = format!("/sync/v1/vaults/{vault}/changes");
    let snapshot_path = format!("/sync/v1/vaults/{vault}/snapshot");
    let history_path = format!("/sync/v1/vaults/{vault}/objects/{object}/versions");
    for path in [&changes_path, &snapshot_path, &history_path] {
        let read_proof = proof("GET", path, &token);
        let target =
            if path == &history_path { path.clone() } else { format!("{path}?after=0&limit=1000") };
        let response = http(
            address,
            "GET",
            &target,
            &[],
            &[("Authorization", authorization.as_str()), ("DPoP", read_proof.as_str())],
        )
        .await;
        assert_eq!(response.status, 200, "{path}");
        let payload = if path == &changes_path {
            SyncChangesResponse::from_cbor_with_limits(&response.body, reads)
                .expect("large changes")
                .changes
                .remove(0)
                .payload
        } else if path == &snapshot_path {
            SyncSnapshotResponse::from_cbor_with_limits(&response.body, reads)
                .expect("large snapshot")
                .objects
                .remove(0)
                .payload
        } else {
            SyncVersionsResponse::from_cbor_with_limits(&response.body, reads)
                .expect("large history")
                .versions
                .remove(0)
                .payload
        };
        assert_eq!(payload, write.payload);
    }
    let too_large = SyncWriteBatch {
        writes: vec![signed_opaque_write(vault, device, Uuid::now_v7(), 266_242)],
    };
    let encoding = scoplen_api::sync::SyncWriteLimits {
        max_envelope_bytes: 266_242,
        ..limits().codec_limits()
    };
    let oversized =
        too_large.to_cbor_with_limits(encoding).expect("valid but oversized signed envelope");
    let write_proof = proof("POST", &objects_path, &token);
    problem(
        &http(
            address,
            "POST",
            &objects_path,
            &oversized,
            &write_headers(&authorization, &write_proof),
        )
        .await,
        413,
        "sync.invalid_request",
    );
    let mut bad_signature = batch;
    let last = bad_signature.writes[0].payload.len() - 1;
    bad_signature.writes[0].payload[last] ^= 1;
    let bad_body =
        bad_signature.to_cbor_with_limits(limits().codec_limits()).expect("bad signature body");
    let write_proof = proof("POST", &objects_path, &token);
    problem(
        &http(
            address,
            "POST",
            &objects_path,
            &bad_body,
            &write_headers(&authorization, &write_proof),
        )
        .await,
        400,
        "sync.invalid_request",
    );
    server.abort();
    let _ = server.await;
}

#[tokio::test]
async fn sqlite_listener_configurable_sync_limits_verify_real_device_signatures() {
    let directory = directory();
    let store = SqliteStore::open_with_sync_limits(
        &directory.join("scoplen.sqlite"),
        scoplen_store::sync::SyncCardinalityLimits::default(),
        limits().codec_limits(),
    )
    .await
    .expect("configured SQLite");
    let (_, device, vault) = seed_sqlite(&store).await;
    exercise_listener(ListenerDatabase::Sqlite(Arc::new(store.clone())), &directory, device, vault)
        .await;
    assert_eq!(
        store.sync_changes(vault.into_bytes(), 0, 10).await.expect("atomic failures").next_cursor,
        1
    );
    store.pool().close().await;
    drop(store);
    remove_directory(&directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_listener_configurable_sync_limits_verify_real_device_signatures() {
    let url =
        std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("isolated PostgreSQL test database");
    let directory = directory();
    let store = PostgresStore::connect_with_sync_limits(
        &url,
        scoplen_store::sync::SyncCardinalityLimits::default(),
        limits().codec_limits(),
    )
    .await
    .expect("configured PostgreSQL");
    let (_, device, vault) = seed_postgres(&store).await;
    exercise_listener(
        ListenerDatabase::Postgres(Arc::new(store.clone())),
        &directory,
        device,
        vault,
    )
    .await;
    assert_eq!(
        store.sync_changes(vault.into_bytes(), 0, 10).await.expect("atomic failures").next_cursor,
        1
    );
    store.pool().close().await;
    drop(store);
    remove_directory(&directory).await;
}
