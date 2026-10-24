// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::{
    io::{self, Write},
    sync::Mutex,
    time::{Duration, Instant},
};
use tracing::instrument::WithSubscriber;

#[derive(Clone, Default)]
struct CapturedLogs(Arc<Mutex<Vec<u8>>>);

impl Write for CapturedLogs {
    fn write(&mut self, bytes: &[u8]) -> io::Result<usize> {
        self.0.lock().expect("captured log lock").extend_from_slice(bytes);
        Ok(bytes.len())
    }

    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

impl CapturedLogs {
    fn dispatch(&self) -> tracing::Dispatch {
        let writer = self.clone();
        tracing::Dispatch::new(
            tracing_subscriber::fmt()
                .json()
                .without_time()
                .with_target(false)
                .with_env_filter("scoplen_server::device_auth=debug")
                .with_writer(move || writer.clone())
                .finish(),
        )
    }

    fn events(&self) -> Vec<serde_json::Value> {
        let bytes = self.0.lock().expect("captured log lock");
        bytes
            .split(|byte| *byte == b'\n')
            .filter(|line| !line.is_empty())
            .map(|line| serde_json::from_slice(line).expect("structured event"))
            .collect()
    }

    fn assert_storage_failure(&self, request_id: &str, phase: &str, kind: &str) {
        let events = self.events();
        for event in &events {
            let fields = event["fields"].as_object().expect("event fields");
            assert!(fields.keys().all(|key| matches!(
                key.as_str(),
                "message" | "request_id" | "endpoint" | "phase" | "error_kind" | "elapsed_ms"
            )));
            assert!(fields["request_id"].as_str().is_some_and(|value| !value.is_empty()));
        }
        let failures: Vec<_> = events
            .iter()
            .filter(|event| event["fields"]["request_id"] == request_id)
            .filter(|event| event["level"] == "WARN")
            .collect();
        assert_eq!(failures.len(), 1);
        let fields = &failures[0]["fields"];
        assert_eq!(fields["message"], "authentication storage operation failed");
        assert_eq!(fields["endpoint"], "Refresh");
        assert_eq!(fields["phase"], phase);
        assert_eq!(fields["error_kind"], kind);
        assert!(fields["elapsed_ms"].as_u64().is_some());
    }
}

struct Fixture {
    store: SqliteStore,
    server: tokio::task::JoinHandle<()>,
    directory: PathBuf,
    address: SocketAddr,
    device: Uuid,
    vault: Uuid,
    token: AuthTokenResponse,
    logs: CapturedLogs,
}

impl Fixture {
    async fn new() -> Self {
        let directory = directory();
        let store = SqliteStore::open(&directory.join("scoplen.sqlite")).await.expect("store");
        let kms = key_management(&directory);
        let (_, device) = seed_sqlite_identity(&store).await;
        let vault = Uuid::now_v7();
        store
            .create_sync_vault(vault.into_bytes(), scoplen_store::sync::VaultKind::Personal)
            .await
            .expect("test vault");
        let keyring = store.ensure_device_token_keyring(&*kms).await.expect("keyring");
        let challenge = store.issue_device_challenge(device.into_bytes()).await.expect("challenge");
        let context = DeviceAuthContext::new(ORIGIN, &hex(challenge.nonce()), device)
            .expect("signature context");
        let token = store
            .authenticate_device(
                "127.0.0.1".parse().expect("source"),
                ORIGIN,
                device.into_bytes(),
                challenge.nonce(),
                &device_key().sign(&context.signature_input()),
                &keyring,
            )
            .await
            .expect("initial device token");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("listener");
        let address = listener.local_addr().expect("address");
        let backend = AuthBackend::Sqlite(Arc::new(store.clone()));
        let logs = CapturedLogs::default();
        let dispatch = logs.dispatch();
        let app = router(ORIGIN.into(), backend, kms).layer(axum::middleware::from_fn(
            move |request: Request<Body>, next: axum::middleware::Next| {
                next.run(request).with_subscriber(dispatch.clone())
            },
        ));
        let server = tokio::spawn(async move {
            axum::serve(listener, app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("serve auth HTTP");
        });
        Self { store, server, directory, address, device, vault, token, logs }
    }

    async fn rotate(&mut self) -> HttpReply {
        let body = AuthRefreshRequest::new(&self.token.refresh_token)
            .expect("refresh request")
            .to_json()
            .expect("JSON");
        let response = http(
            self.address,
            "POST",
            "/api/v1/auth/refresh",
            &body,
            &[("Content-Type", "application/json"), ("DPoP", &proof())],
        )
        .await;
        if response.status == 200 {
            self.token = AuthTokenResponse::from_json(response.body_text()).expect("rotated token");
        }
        response
    }

    async fn close(self) {
        self.server.abort();
        let _ = self.server.await;
        self.store.pool().close().await;
        drop(self.store);
        crate::test_support::remove_test_directory(self.directory).await;
    }
}

#[tokio::test]
async fn sqlite_refresh_writer_timeout_preserves_admission_and_credentials() {
    let mut fixture = Fixture::new().await;
    for _ in 0..2 {
        assert_eq!(fixture.rotate().await.status, 200);
    }
    let attempts: i64 = sqlx::query_scalar(
        "SELECT attempts FROM device_auth_admission WHERE endpoint=3 AND kind=1",
    )
    .fetch_one(fixture.store.pool())
    .await
    .expect("source attempts");
    assert_eq!(attempts, 2);
    let events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
        .fetch_one(fixture.store.pool())
        .await
        .expect("audit count");
    let writer = fixture.store.pool().begin_with("BEGIN IMMEDIATE").await.expect("external writer");
    // WAL readers, including the notification authorization and actual bounded sync reader,
    // do not acquire the writer reservation while the unrelated writer is held.
    assert!(
        fixture
            .store
            .current_device_principal(fixture.device.into_bytes())
            .await
            .expect("reader")
            .is_some()
    );
    assert_eq!(
        fixture
            .store
            .sync_changes_with_read_limits(
                fixture.vault.into_bytes(),
                0,
                1,
                scoplen_api::sync::SyncReadLimits::default(),
            )
            .await
            .expect("bounded WAL reader")
            .changes
            .len(),
        0
    );
    let start = Instant::now();
    let rejected = tokio::time::timeout(Duration::from_secs(15), fixture.rotate())
        .await
        .expect("production busy timeout bounds admission");
    assert!(start.elapsed() >= Duration::from_secs(4));
    rejected.problem(503, "auth.storage_unavailable", false);
    let problem: ProblemDetails = serde_json::from_slice(&rejected.body).expect("problem");
    assert!(problem.retryable);
    fixture.logs.assert_storage_failure(&problem.instance, "source_admission", "database_busy");
    {
        let logs = fixture.logs.0.lock().expect("captured log lock");
        assert!(!String::from_utf8_lossy(&logs).contains(&fixture.token.refresh_token));
    }
    let unchanged: (i64, i64, i64) = sqlx::query_as(
        "SELECT attempts, failure_streak, COALESCE(cooldown_until_ms, 0) FROM device_auth_admission WHERE endpoint=3 AND kind=1",
    )
    .fetch_one(fixture.store.pool())
    .await
    .expect("admission state");
    assert_eq!(unchanged, (2, 0, 0));
    let retained_events: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM deployment_audit_events")
        .fetch_one(fixture.store.pool())
        .await
        .expect("audit count");
    assert_eq!(retained_events, events);
    let spent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_refresh_tokens WHERE spent_at_ms IS NOT NULL",
    )
    .fetch_one(fixture.store.pool())
    .await
    .expect("spent credentials");
    assert_eq!(spent, 2);
    writer.rollback().await.expect("release external writer");
    // A deliberate new request after a confirmed no-change rejection is distinct from
    // replaying an unknown refresh commit. Its proof is newly generated by rotate().
    assert_eq!(fixture.rotate().await.status, 200);
    fixture.close().await;
}

#[tokio::test]
async fn sqlite_refresh_closed_pool_has_correlated_redacted_diagnostics() {
    let mut fixture = Fixture::new().await;
    fixture.store.pool().close().await;
    let rejected = fixture.rotate().await;
    rejected.problem(503, "auth.storage_unavailable", false);
    let problem: ProblemDetails = serde_json::from_slice(&rejected.body).expect("problem");
    assert!(problem.retryable);
    fixture.logs.assert_storage_failure(&problem.instance, "source_admission", "pool_closed");
    fixture.close().await;
}

#[tokio::test]
async fn sqlite_refresh_keyring_failure_logs_its_phase_without_consuming_token() {
    let mut fixture = Fixture::new().await;
    sqlx::query(
        "UPDATE device_access_token_keys SET encrypted_seed = zeroblob(73) WHERE active_slot = 1",
    )
    .execute(fixture.store.pool())
    .await
    .expect("corrupt isolated fixture keyring");
    let rejected = fixture.rotate().await;
    rejected.problem(503, "auth.storage_unavailable", false);
    let problem: ProblemDetails = serde_json::from_slice(&rejected.body).expect("problem");
    assert!(problem.retryable);
    fixture.logs.assert_storage_failure(&problem.instance, "keyring", "database");
    let spent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_refresh_tokens WHERE spent_at_ms IS NOT NULL",
    )
    .fetch_one(fixture.store.pool())
    .await
    .expect("unconsumed credential");
    assert_eq!(spent, 0);
    fixture.close().await;
}

#[tokio::test]
async fn sqlite_refresh_audit_failure_logs_transaction_phase_and_rolls_back() {
    let mut fixture = Fixture::new().await;
    sqlx::query("CREATE TRIGGER diagnostics_fail_audit BEFORE INSERT ON deployment_audit_events BEGIN SELECT RAISE(ABORT, 'private-audit-detail-must-not-be-logged'); END")
        .execute(fixture.store.pool()).await.expect("isolated fixture audit failure");
    let rejected = fixture.rotate().await;
    rejected.problem(503, "auth.storage_unavailable", false);
    let problem: ProblemDetails = serde_json::from_slice(&rejected.body).expect("problem");
    assert!(problem.retryable);
    fixture.logs.assert_storage_failure(&problem.instance, "refresh_transaction", "audit");
    {
        let logs = fixture.logs.0.lock().expect("captured log lock");
        assert!(!String::from_utf8_lossy(&logs).contains("private-audit-detail"));
    }
    let spent: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM device_refresh_tokens WHERE spent_at_ms IS NOT NULL",
    )
    .fetch_one(fixture.store.pool())
    .await
    .expect("rolled-back credential");
    assert_eq!(spent, 0);
    sqlx::query("DROP TRIGGER diagnostics_fail_audit")
        .execute(fixture.store.pool())
        .await
        .expect("release isolated fixture failure");
    assert_eq!(fixture.rotate().await.status, 200);
    fixture.close().await;
}

#[tokio::test]
async fn storage_error_classification_and_logging_preserve_recovery_flags() {
    const PRIVATE_DETAIL: &str = "private-database-content-must-not-survive";
    let cases = [
        (DeviceAuthenticationError::from(sqlx::Error::PoolTimedOut), "pool_timeout"),
        (DeviceAuthenticationError::from(sqlx::Error::PoolClosed), "pool_closed"),
        (DeviceAuthenticationError::from(sqlx::Error::Protocol(PRIVATE_DETAIL.into())), "database"),
        (DeviceAuthenticationError::Audit, "audit"),
        (DeviceAuthenticationError::Clock, "clock"),
        (DeviceAuthenticationError::Entropy, "entropy"),
        (DeviceAuthenticationError::CommitOutcomeUnknown, "commit_outcome_unknown"),
    ];
    let logs = CapturedLogs::default();
    for (error, kind) in cases {
        let request_id = Uuid::new_v4().to_string();
        tracing::dispatcher::with_default(&logs.dispatch(), || {
            log_auth_storage_failure(
                &error,
                DeviceAuthEndpoint::Refresh,
                "refresh_transaction",
                &request_id,
                Instant::now(),
            );
        });
        logs.assert_storage_failure(&request_id, "refresh_transaction", kind);
        assert!(!format!("{error:?}: {error}").contains(PRIVATE_DETAIL));
        let response = business_problem(&error, &request_id);
        assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
        let body = to_bytes(response.into_body(), 4096).await.expect("problem body");
        let problem: ProblemDetails = serde_json::from_slice(&body).expect("problem");
        let unknown = matches!(error, DeviceAuthenticationError::CommitOutcomeUnknown);
        assert_eq!(problem.changed, unknown);
        assert_eq!(problem.retryable, !unknown);
    }
    assert!(
        !String::from_utf8_lossy(&logs.0.lock().expect("captured log lock"))
            .contains(PRIVATE_DETAIL)
    );
}

#[tokio::test]
async fn sqlite_cancelled_admission_wait_releases_connections_and_writer_lock() {
    let fixture = Fixture::new().await;
    let writer = fixture.store.pool().begin_with("BEGIN IMMEDIATE").await.expect("external writer");
    for _ in 0..4 {
        let cancelled = tokio::time::timeout(
            Duration::from_millis(100),
            fixture.store.admit_device_auth_source(
                DeviceAuthEndpoint::Refresh,
                "127.0.0.1".parse().expect("source"),
            ),
        )
        .await;
        assert!(cancelled.is_err(), "the held writer must prevent admission");
    }
    writer.rollback().await.expect("release external writer");
    let admission = tokio::time::timeout(
        Duration::from_secs(15),
        fixture.store.admit_device_auth_source(
            DeviceAuthEndpoint::Refresh,
            "127.0.0.1".parse().expect("source"),
        ),
    )
    .await
    .expect("cancelled BEGINs cannot leak the pool or writer lock")
    .expect("fresh admission");
    assert_eq!(admission, DeviceAuthAdmission::Admitted);
    let attempts: i64 = sqlx::query_scalar(
        "SELECT attempts FROM device_auth_admission WHERE endpoint=3 AND kind=1",
    )
    .fetch_one(fixture.store.pool())
    .await
    .expect("only the acknowledged attempt is charged");
    assert_eq!(attempts, 1);
    fixture.close().await;
}
