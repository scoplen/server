// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

fn descriptor(device: Uuid) -> Object {
    let mut object = Object::new(Uuid::now_v7(), ObjectType::CREDENTIAL, 1).expect("credential");
    for (field, value) in [
        (1, cbor::Value::Text("Interactive login".into())),
        (2, cbor::Value::UInt(8)),
        (3, cbor::Value::UInt(3)),
    ] {
        object
            .insert(
                FieldPath::field(field).expect("field"),
                FieldEntry::new(value, Hlc::at(1).expect("clock"), device).expect("entry"),
            )
            .expect("insert");
    }
    object.validate().expect("D-123 descriptor");
    object
}

async fn exchange(
    database: ListenerDatabase,
    directory: &std::path::Path,
    device: Uuid,
    vault: Uuid,
) {
    let objects = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
        root: directory.join("objects"),
    })
    .expect("objects");
    let app = api_router_with_limits(
        database,
        Arc::new(objects),
        kms(directory),
        ORIGIN.into(),
        true,
        WriteRateLimits::default(),
        WriteBodyLimits::default(),
        ReadBodyLimits::default(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
    let address = listener.local_addr().expect("address");
    let server = tokio::spawn(async move {
        axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
            .await
            .expect("serve");
    });
    let result =
        tokio::time::timeout(Duration::from_secs(30), verify_exchange(address, device, vault))
            .await;
    server.abort();
    let _ = server.await;
    result.expect("interactive credential exchange exceeded its deadline");
}

async fn verify_exchange(address: SocketAddr, device: Uuid, vault: Uuid) {
    let token = issue_token(address, device).await;
    let authorization = format!("DPoP {token}");
    let object = descriptor(device);
    let key = SecretBytes::new([8; 32]);
    let payload = ObjectEnvelope::encrypt(vault, 1, &object, &key, device, &device_key())
        .expect("encrypt and sign")
        .encode()
        .expect("envelope");
    let write = SyncWrite {
        object_id: object.id,
        base_seq: None,
        payload: payload.clone(),
        tombstone: false,
    };
    let path = format!("/sync/v1/vaults/{vault}/objects");
    for (candidate, status) in [(write.clone(), 200), {
        let mut damaged = write;
        *damaged.payload.last_mut().expect("signature") ^= 1;
        (damaged, 400)
    }] {
        let body = SyncWriteBatch { writes: vec![candidate] }.to_cbor().expect("batch");
        let proof = proof("POST", &path, &token);
        let headers = [
            ("Content-Type", "application/cbor"),
            ("Authorization", authorization.as_str()),
            ("DPoP", proof.as_str()),
        ];
        let reply = http(address, "POST", &path, &body, &headers).await;
        assert_eq!(reply.status, status);
        if status == 200 {
            let response = SyncWriteBatchResponse::from_cbor(&reply.body).expect("assignment");
            assert_eq!(response.assignments.len(), 1);
            assert_eq!(response.assignments[0].object_id, object.id);
            assert_eq!(response.assignments[0].seq, 1);
        } else {
            problem(&reply, 400, "sync.invalid_request");
        }
    }
    let snapshot_path = format!("/sync/v1/vaults/{vault}/snapshot");
    let proof = proof("GET", &snapshot_path, &token);
    let headers = [("Authorization", authorization.as_str()), ("DPoP", proof.as_str())];
    let reply =
        http(address, "GET", &format!("{snapshot_path}?after=0&limit=10"), &[], &headers).await;
    assert_eq!(reply.status, 200);
    let snapshot = SyncSnapshotResponse::from_cbor(&reply.body).expect("snapshot");
    assert_eq!(snapshot.objects.len(), 1);
    assert_eq!(snapshot.next_cursor, 1);
    assert!(!snapshot.more);
    let retained = &snapshot.objects[0];
    assert_eq!(retained.object_id, object.id);
    assert_eq!(retained.signer_device_id, Some(device));
    assert_eq!(retained.payload, payload);
    let reopened = ObjectEnvelope::decode(&retained.payload)
        .expect("retained envelope")
        .decrypt(vault, object.id, &key, &device_key().public_key_sec1())
        .expect("verify, decrypt and validate on the receiving side");
    assert_eq!(reopened, object);
}

#[tokio::test]
async fn sqlite_listener_preserves_interactive_credential_envelope() {
    let directory = directory();
    let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
    let (_, device, vault) = seed_sqlite(&store).await;
    exchange(ListenerDatabase::Sqlite(Arc::new(store.clone())), &directory, device, vault).await;
    store.pool().close().await;
    drop(store);
    remove_directory(&directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_listener_preserves_interactive_credential_envelope() {
    let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let directory = directory();
    let store = PostgresStore::connect(&database_url).await.expect("PostgreSQL store");
    let (_, device, vault) = seed_postgres(&store).await;
    exchange(ListenerDatabase::Postgres(Arc::new(store.clone())), &directory, device, vault).await;
    store.pool().close().await;
    drop(store);
    remove_directory(&directory).await;
}
