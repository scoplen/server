// SPDX-License-Identifier: AGPL-3.0-only

use super::*;

#[test]
fn budgeted_read_prefixes_preserve_cursors_and_validate_the_whole_source_page() {
    let entries = [23, 24, 256]
        .map(|seq| api::SyncChange {
            object_id: Uuid::now_v7(),
            seq,
            payload: vec![1; 32],
            tombstone: false,
            signer_device_id: Some(Uuid::now_v7()),
        })
        .to_vec();
    let query = api::SyncChangesQuery { after: 0, limit: 1_000 };
    for snapshot in [false, true] {
        let page = |entries, next_cursor, more| {
            if snapshot {
                ReadPage::Snapshot(api::SyncSnapshotResponse {
                    objects: entries,
                    next_cursor,
                    more,
                })
            } else {
                ReadPage::Changes(api::SyncChangesResponse { changes: entries, next_cursor, more })
            }
        };
        let decode = |body: &[u8]| {
            if snapshot {
                let result = api::SyncSnapshotResponse::from_cbor(body).expect("snapshot prefix");
                api::SyncChangesResponse {
                    changes: result.objects,
                    next_cursor: result.next_cursor,
                    more: result.more,
                }
            } else {
                api::SyncChangesResponse::from_cbor(body).expect("changes prefix")
            }
        };
        let exact_prefix = page(entries[..2].to_vec(), 24, true)
            .encode_prefix(&query, api::SyncReadLimits::default(), "test")
            .expect("exact two-entry encoding");
        let limits =
            api::SyncReadLimits { max_envelope_bytes: 32, max_body_bytes: exact_prefix.len() };
        for (cursor, more) in [(256, true), (512, false)] {
            let body = page(entries.clone(), cursor, more)
                .encode_prefix(&query, limits, "test")
                .expect("largest prefix");
            assert_eq!(body, exact_prefix);
            let body = page(entries.clone(), cursor, more)
                .encode_prefix(&query, api::SyncReadLimits::default(), "test")
                .expect("complete source fits");
            let result = decode(&body);
            assert_eq!(result.changes, entries);
            assert_eq!(result.next_cursor, cursor);
            assert_eq!(result.more, more);
        }
        for defect in 0..3 {
            let mut invalid = entries.clone();
            let mut cursor = 512;
            match defect {
                0 => invalid[2].object_id = invalid[0].object_id,
                1 => invalid[2].seq = invalid[1].seq,
                _ => cursor = 24,
            }
            assert!(page(invalid, cursor, false).encode_prefix(&query, limits, "test").is_err());
        }
        let empty_query = api::SyncChangesQuery { after: 512, limit: 1_000 };
        let body = page(Vec::new(), 512, false)
            .encode_prefix(&empty_query, api::SyncReadLimits::default(), "test")
            .expect("empty final page");
        let result = decode(&body);
        assert_eq!(result.changes, Vec::new());
        assert_eq!(result.next_cursor, 512);
        assert!(!result.more);
        assert!(
            page(Vec::new(), 512, false)
                .encode_prefix(
                    &empty_query,
                    api::SyncReadLimits { max_body_bytes: 1, ..limits },
                    "test",
                )
                .is_err()
        );
    }
}

#[test]
fn complete_conflict_cap_and_request_binding_fail_closed() {
    let object = Uuid::now_v7();
    let batch = SyncWriteBatch {
        writes: vec![api::SyncWrite {
            object_id: object,
            base_seq: None,
            payload: vec![1],
            tombstone: false,
        }],
    };
    let limits = api::SyncWriteLimits {
        max_envelope_bytes: api::MAX_SYNC_CONFLICT_BODY_BYTES,
        max_batch_objects: 1,
        max_batch_bytes: 128,
    };
    let oversized = storage::ConflictEntry {
        object_id: object.into_bytes(),
        current: Some(storage::SyncChange {
            object_id: object.into_bytes(),
            sequence: 1,
            envelope: vec![1; api::MAX_SYNC_CONFLICT_BODY_BYTES],
            key_epoch: 1,
            tombstone: false,
            signer_device_id: None,
        }),
    };
    let error = SyncHttpError::from_write_store(
        storage::SyncStoreError::Conflict { conflicts: vec![oversized] },
        &batch,
        limits,
        "test-cap",
    );
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert_eq!(error.problem.code.as_str(), "sync.storage_unavailable");
    assert!(!error.problem.changed);
    assert!(error.body.is_none(), "never emit a partial conflicts extension");
    let error = SyncHttpError::from_write_store(
        storage::SyncStoreError::Conflict {
            conflicts: vec![storage::ConflictEntry {
                object_id: Uuid::now_v7().into_bytes(),
                current: None,
            }],
        },
        &batch,
        limits,
        "test-binding",
    );
    assert_eq!(error.status, StatusCode::SERVICE_UNAVAILABLE);
    assert!(error.body.is_none());
}

fn raised_limits() -> WriteBodyLimits {
    WriteBodyLimits::new(266_241, 501, 4_800_000).expect("raised deployment limits")
}

#[tokio::test]
async fn committed_write_with_invalid_receipts_never_claims_rollback_or_safe_retry() {
    let (store, vault, device) = test_store().await;
    let mut auth = TestAuthenticator::new(device, true);
    auth.truncate_write_receipts = Some(0);
    let app = router(store.clone(), auth);
    let batch = SyncWriteBatch {
        writes: vec![api::SyncWrite {
            object_id: Uuid::now_v7(),
            base_seq: None,
            payload: vec![1],
            tombstone: false,
        }],
    };
    let response = app.oneshot(write_request(vault, &batch)).await.expect("invalid receipt");
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let body = to_bytes(response.into_body(), 4_096).await.expect("problem");
    let problem = ProblemDetails::from_cbor(&body).expect("committed failure");
    assert!(problem.changed);
    assert!(!problem.retryable);
    assert_eq!(store.sync_changes(vault, 0, 10).await.expect("committed object").next_cursor, 1);
    store.pool().close().await;
}

fn configured_request(
    vault: storage::VaultId,
    batch: &SyncWriteBatch,
    limits: api::SyncWriteLimits,
) -> Request<Body> {
    request_headers(
        Request::builder()
            .method("POST")
            .uri(format!("/sync/v1/vaults/{}/objects", path(vault)))
            .header(header::CONTENT_TYPE, "application/cbor"),
    )
    .body(Body::from(batch.to_cbor_with_limits(limits).expect("encode selected limits")))
    .expect("write request")
}

async fn read(app: &Router, uri: String) -> Response {
    app.clone()
        .oneshot(request_headers(Request::builder().uri(uri)).body(Body::empty()).expect("read"))
        .await
        .expect("read response")
}

async fn bounded_pages(
    app: &Router,
    vault: storage::VaultId,
    endpoint: &str,
    budgets: ReadBodyLimits,
) -> Vec<api::SyncChange> {
    let mut all = Vec::new();
    let mut after = 0;
    loop {
        let uri = format!("/sync/v1/vaults/{}/{endpoint}?after={after}&limit=1000", path(vault));
        let response = read(app, uri).await;
        assert_eq!(response.status(), StatusCode::OK, "fixed-limit paging must progress");
        let body =
            to_bytes(response.into_body(), budgets.0.max_body_bytes).await.expect("bounded page");
        let query = api::SyncChangesQuery { after, limit: 1_000 };
        let (entries, cursor, more) = if endpoint == "changes" {
            let page = api::SyncChangesResponse::from_cbor_with_limits(&body, budgets.0)
                .expect("budgeted changes page");
            page.validate_for_query_with_limits(&query, budgets.0).expect("correlated changes");
            (page.changes, page.next_cursor, page.more)
        } else {
            let page = api::SyncSnapshotResponse::from_cbor_with_limits(&body, budgets.0)
                .expect("budgeted snapshot page");
            page.validate_for_query_with_limits(&query, budgets.0).expect("correlated snapshot");
            (page.objects, page.next_cursor, page.more)
        };
        if more {
            assert!(!entries.is_empty(), "non-final pages must make progress");
            assert_eq!(cursor, entries.last().expect("last eligible entry").seq);
        }
        all.extend(entries);
        if !more {
            assert_eq!(cursor, 502, "final page retains the storage snapshot cursor");
            break;
        }
        assert!(cursor > after);
        after = cursor;
    }
    all
}

#[allow(clippy::too_many_lines)]
async fn round_trip(store: SyncBackend, vault: storage::VaultId) -> Uuid {
    let limits = raised_limits();
    let reads = ReadBodyLimits::new(266_241, 6_000_000).expect("independent read budget");
    let device = Uuid::now_v7().into_bytes();
    let app = router_with_limits(
        store.clone(),
        TestAuthenticator::new(device, true),
        NotificationHub::default(),
        WriteRateLimits::default(),
        limits,
        reads,
    );
    let batch = SyncWriteBatch {
        writes: (0..501)
            .map(|index| api::SyncWrite {
                object_id: Uuid::now_v7(),
                base_seq: None,
                payload: vec![1; if index == 0 { 266_241 } else { 9_000 }],
                tombstone: false,
            })
            .collect(),
    };
    assert!(
        batch.to_cbor_with_limits(limits.codec_limits()).expect("encoded batch").len()
            > MAX_REQUEST_BYTES
    );
    let response = app
        .clone()
        .oneshot(configured_request(vault, &batch, limits.codec_limits()))
        .await
        .expect("raised write response");
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 30_000).await.expect("assignments");
    let assignments =
        api::SyncWriteBatchResponse::from_cbor_with_limits(&body, limits.codec_limits())
            .expect("all 501 assignments");
    assignments
        .validate_for_batch_with_limits(&batch, limits.codec_limits())
        .expect("request order");
    assert_eq!(assignments.assignments.len(), 501);

    let object = batch.writes[0].object_id;
    let update = SyncWriteBatch {
        writes: vec![api::SyncWrite {
            object_id: object,
            base_seq: Some(1),
            payload: vec![2; 266_241],
            tombstone: false,
        }],
    };
    assert_eq!(
        app.clone()
            .oneshot(configured_request(vault, &update, limits.codec_limits()))
            .await
            .expect("update")
            .status(),
        StatusCode::OK
    );
    let response = app
        .clone()
        .oneshot(configured_request(vault, &batch, limits.codec_limits()))
        .await
        .expect("complete stale batch");
    assert_eq!(response.status(), StatusCode::CONFLICT);
    let body = to_bytes(response.into_body(), 6_000_000).await.expect("complete conflicts");
    let conflicts = api::SyncConflictProblem::from_cbor_with_limits(&body, limits.codec_limits())
        .expect("all conflicts use deployment limits");
    conflicts
        .validate_for_batch_with_limits(&batch, limits.codec_limits())
        .expect("conflict order");
    assert_eq!(conflicts.conflicts.len(), 501);
    assert_eq!(conflicts.conflicts[0].current.as_ref().expect("current").seq, 502);

    let changes_uri = format!("/sync/v1/vaults/{}/changes?after=0&limit=1000", path(vault));
    let snapshot_uri = format!("/sync/v1/vaults/{}/snapshot?after=0&limit=1000", path(vault));
    let history_uri = format!("/sync/v1/vaults/{}/objects/{object}/versions", path(vault));
    let response = read(&app, changes_uri.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 6_000_000).await.expect("changes");
    let changes =
        api::SyncChangesResponse::from_cbor_with_limits(&body, reads.0).expect("changes codec");
    assert_eq!(changes.changes.len(), 501);
    assert_eq!(changes.next_cursor, 502);
    let response = read(&app, snapshot_uri.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 6_000_000).await.expect("snapshot");
    let snapshot =
        api::SyncSnapshotResponse::from_cbor_with_limits(&body, reads.0).expect("snapshot codec");
    assert_eq!(snapshot.objects.len(), 501);
    let response = read(&app, history_uri.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let body = to_bytes(response.into_body(), 600_000).await.expect("history");
    let history =
        api::SyncVersionsResponse::from_cbor_with_limits(&body, reads.0).expect("history codec");
    assert_eq!(history.versions.len(), 2);
    assert!(history.versions.iter().all(|version| version.payload.len() == 266_241));

    let page_budget = ReadBodyLimits::new(266_241, 266_350).expect("fits the largest single entry");
    let paged = router_with_limits(
        store.clone(),
        TestAuthenticator::new(device, true),
        NotificationHub::default(),
        WriteRateLimits::default(),
        limits,
        page_budget,
    );
    for endpoint in ["changes", "snapshot"] {
        assert_eq!(bounded_pages(&paged, vault, endpoint, page_budget).await, changes.changes);
    }
    assert_eq!(
        read(&paged, history_uri.clone()).await.status(),
        StatusCode::SERVICE_UNAVAILABLE,
        "unpaged history is complete or fails without partial results"
    );

    let encoding = api::SyncWriteLimits {
        max_envelope_bytes: 266_242,
        max_batch_objects: 502,
        ..limits.codec_limits()
    };
    let mut too_many = batch.clone();
    too_many.writes.push(api::SyncWrite {
        object_id: Uuid::now_v7(),
        base_seq: None,
        payload: vec![1],
        tombstone: false,
    });
    let too_large = SyncWriteBatch {
        writes: vec![api::SyncWrite {
            object_id: Uuid::now_v7(),
            base_seq: None,
            payload: vec![1; 266_242],
            tombstone: false,
        }],
    };
    for rejected in [&too_many, &too_large] {
        let response = app
            .clone()
            .oneshot(configured_request(vault, rejected, encoding))
            .await
            .expect("limit rejection");
        assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);
        let body = to_bytes(response.into_body(), 4_096).await.expect("problem");
        let problem = ProblemDetails::from_cbor(&body).expect("limit problem");
        assert_eq!(problem.code.as_str(), "sync.invalid_request");
        assert!(!problem.changed);
    }

    let lower = router_with_limits(
        store.clone(),
        TestAuthenticator::new(device, true),
        NotificationHub::default(),
        WriteRateLimits::default(),
        WriteBodyLimits::new(1, 1, 128).expect("lower writes"),
        reads,
    );
    for uri in [&changes_uri, &snapshot_uri, &history_uri] {
        assert_eq!(
            read(&lower, uri.clone()).await.status(),
            StatusCode::OK,
            "lower writes do not strand retained history"
        );
    }
    let response = lower
        .oneshot(configured_request(vault, &update, limits.codec_limits()))
        .await
        .expect("lower write");
    assert_eq!(response.status(), StatusCode::PAYLOAD_TOO_LARGE);

    for budgets in [
        ReadBodyLimits::new(266_240, 6_000_000).expect("lower payload"),
        ReadBodyLimits::new(266_241, 1).expect("lower body"),
    ] {
        let bounded = router_with_limits(
            store.clone(),
            TestAuthenticator::new(device, true),
            NotificationHub::default(),
            WriteRateLimits::default(),
            limits,
            budgets,
        );
        if budgets.0.max_envelope_bytes < reads.0.max_envelope_bytes {
            let response = read(&bounded, changes_uri.clone()).await;
            assert_eq!(response.status(), StatusCode::OK, "return the prefix before a large entry");
            let body = to_bytes(response.into_body(), budgets.0.max_body_bytes)
                .await
                .expect("prefix before the large entry");
            let prefix = api::SyncChangesResponse::from_cbor_with_limits(&body, budgets.0)
                .expect("payload-bounded prefix");
            assert_eq!(prefix.changes.len(), 500);
            assert_eq!(prefix.next_cursor, 501);
            assert!(prefix.more);
        }
        for uri in [
            format!("/sync/v1/vaults/{}/changes?after=501&limit=1000", path(vault)),
            format!("/sync/v1/vaults/{}/snapshot?after=501&limit=1000", path(vault)),
            history_uri.clone(),
        ] {
            let response = read(&bounded, uri).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let body = to_bytes(response.into_body(), 4_096).await.expect("read failure");
            let problem = ProblemDetails::from_cbor(&body).expect("read budget problem");
            assert_eq!(problem.code.as_str(), "sync.storage_unavailable");
            assert!(!problem.changed);
        }
    }
    assert_eq!(
        store.sync_changes(vault, 0, 1_000).await.expect("unchanged store").next_cursor,
        502
    );
    object
}

#[tokio::test]
async fn sqlite_configurable_sync_limits_round_trip_and_reopen() {
    let directory = std::env::temp_dir().join(format!("scoplen-http-limits-{}", Uuid::new_v4()));
    std::fs::create_dir(&directory).expect("isolated directory");
    let file = directory.join("scoplen.sqlite");
    let store = Arc::new(
        SqliteStore::open_with_sync_limits(
            &file,
            storage::SyncCardinalityLimits::default(),
            raised_limits().codec_limits(),
        )
        .await
        .expect("raised store"),
    );
    let vault = Uuid::now_v7().into_bytes();
    store.create_sync_vault(vault, storage::VaultKind::Personal).await.expect("vault");
    let object = round_trip(store.clone().into(), vault).await;
    store.pool().close().await;
    drop(store);
    let lower = SqliteStore::open_with_sync_limits(
        &file,
        storage::SyncCardinalityLimits::default(),
        WriteBodyLimits::new(1, 1, 128).expect("lower limits").codec_limits(),
    )
    .await
    .expect("reopen lower store");
    assert_eq!(
        lower.sync_versions(vault, object.into_bytes()).await.expect("retained history").len(),
        2
    );
    assert_eq!(
        lower.sync_snapshot(vault, 0, 1_000).await.expect("retained snapshot").objects.len(),
        501
    );
    assert!(matches!(
        lower
            .write_sync_batch(
                vault,
                &[storage::ObjectWrite {
                    object_id: object.into_bytes(),
                    base_sequence: Some(502),
                    envelope: vec![3; 2],
                    key_epoch: 1,
                    tombstone: false,
                    signer_device_id: None,
                }]
            )
            .await,
        Err(storage::SyncStoreError::InvalidEnvelope)
    ));
    assert_eq!(
        lower.sync_changes(vault, 0, 1_000).await.expect("unchanged sequence").next_cursor,
        502
    );
    lower.pool().close().await;
    drop(lower);
    remove_test_directory(&directory).await;
}

#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_configurable_sync_limits_round_trip_and_reopen() {
    let url =
        std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("isolated PostgreSQL test database");
    let store = Arc::new(
        PostgresStore::connect_with_sync_limits(
            &url,
            storage::SyncCardinalityLimits::default(),
            raised_limits().codec_limits(),
        )
        .await
        .expect("raised PostgreSQL store"),
    );
    let vault = Uuid::now_v7().into_bytes();
    store
        .create_shared_sync_vault(vault, TestAuthenticator::account_id(), &[1])
        .await
        .expect("vault");
    let object = round_trip(store.clone().into(), vault).await;
    store.pool().close().await;
    drop(store);
    let lower = PostgresStore::connect_with_sync_limits(
        &url,
        storage::SyncCardinalityLimits::default(),
        WriteBodyLimits::new(1, 1, 128).expect("lower limits").codec_limits(),
    )
    .await
    .expect("reconnect lower store");
    assert_eq!(
        lower.sync_versions(vault, object.into_bytes()).await.expect("retained history").len(),
        2
    );
    assert_eq!(
        lower.sync_snapshot(vault, 0, 1_000).await.expect("retained snapshot").objects.len(),
        501
    );
    assert!(matches!(
        lower
            .write_sync_batch(
                vault,
                &[storage::ObjectWrite {
                    object_id: object.into_bytes(),
                    base_sequence: Some(502),
                    envelope: vec![3; 2],
                    key_epoch: 1,
                    tombstone: false,
                    signer_device_id: None,
                }]
            )
            .await,
        Err(storage::SyncStoreError::InvalidEnvelope)
    ));
    assert_eq!(
        lower.sync_changes(vault, 0, 1_000).await.expect("unchanged sequence").next_cursor,
        502
    );
    lower.pool().close().await;
}
