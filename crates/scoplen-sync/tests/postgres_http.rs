// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(feature = "postgres-integration")]

use std::{
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};

use axum::{
    Router,
    body::{Body, to_bytes},
    http::{HeaderMap, Method, Request, StatusCode, Uri, header},
    response::Response,
};
use futures_util::{SinkExt, StreamExt};
use scoplen_api::{ProblemDetails, sync as api};
use scoplen_model::CURRENT_SCHEMA_VERSION;
use scoplen_store::{PostgresStore, RelationalStore, account_keys as keys, sync as storage};
use scoplen_sync::{
    http::{
        AuthFailure, AuthenticatedDevice, AuthenticatedNotification, KeyUpdateError,
        MAX_REQUEST_BYTES, SyncAuthenticator, SyncBackend, SyncKeysOperation, SyncOperation,
        router_with_notifications,
    },
    notify::NotificationHub,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct TestAuthenticator {
    account: keys::AccountId,
    device: storage::DeviceId,
    vault_access: bool,
    vault: Option<storage::VaultId>,
}

impl TestAuthenticator {
    fn denied() -> AuthFailure {
        AuthFailure::new(
            StatusCode::FORBIDDEN,
            "policy.denied",
            "Sync access denied",
            "The device is not authorized for this vault.",
            false,
        )
        .expect("valid policy failure")
    }
}

#[async_trait::async_trait]
impl SyncAuthenticator for TestAuthenticator {
    type KeyUpdateAuthorization = ();

    async fn authenticate_key_update(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<(AuthenticatedDevice, ()), AuthFailure> {
        self.authenticate(method, uri, headers).await.map(|identity| (identity, ()))
    }

    async fn authenticate(
        &self,
        method: &Method,
        uri: &Uri,
        headers: &HeaderMap,
    ) -> Result<AuthenticatedDevice, AuthFailure> {
        let expected_proof = format!("{method} {uri}");
        if headers.get(header::AUTHORIZATION).and_then(|value| value.to_str().ok())
            != Some("DPoP test-token")
            || headers.get("dpop").and_then(|value| value.to_str().ok())
                != Some(expected_proof.as_str())
        {
            return Err(AuthFailure::new(
                StatusCode::UNAUTHORIZED,
                "auth.authentication_required",
                "Authentication required",
                "The test proof must bind the request method and URI.",
                false,
            )
            .expect("valid authentication failure"));
        }
        Ok(AuthenticatedDevice { device_id: self.device, account_id: self.account })
    }

    async fn authorize(
        &self,
        identity: AuthenticatedDevice,
        vault: storage::VaultId,
        operation: SyncOperation,
    ) -> Result<(), AuthFailure> {
        if self.vault_access
            && identity.account_id == self.account
            && (operation != SyncOperation::Read
                || self.vault.is_none_or(|allowed| vault == allowed))
        {
            Ok(())
        } else {
            Err(Self::denied())
        }
    }

    async fn validate_write(
        &self,
        _identity: AuthenticatedDevice,
        _vault: storage::VaultId,
        writes: &[api::SyncWrite],
    ) -> Result<Vec<u64>, AuthFailure> {
        Ok(vec![1; writes.len()])
    }

    async fn account_id(
        &self,
        _identity: AuthenticatedDevice,
    ) -> Result<keys::AccountId, AuthFailure> {
        Ok(self.account)
    }

    async fn authorize_session(&self, _identity: AuthenticatedDevice) -> Result<(), AuthFailure> {
        Ok(())
    }

    async fn authorize_keys(
        &self,
        _identity: AuthenticatedDevice,
        _account_id: keys::AccountId,
        _operation: SyncKeysOperation,
    ) -> Result<(), AuthFailure> {
        Ok(())
    }

    async fn commit_key_update(
        &self,
        _identity: AuthenticatedDevice,
        account_id: keys::AccountId,
        _authorization: &(),
        update: &api::SyncAccountKeyBundleUpdate,
        store: &SyncBackend,
    ) -> Result<keys::AccountKeyBundlePut, KeyUpdateError> {
        let stored = keys::AccountKeyBundleUpdate::try_from(update)?;
        Ok(match store {
            SyncBackend::Sqlite(store) => store.put_account_key_bundle(account_id, &stored).await?,
            SyncBackend::Postgres(store) => {
                store.put_account_key_bundle(account_id, &stored).await?
            }
        })
    }

    async fn authorize_notifications(
        &self,
        identity: AuthenticatedDevice,
    ) -> Result<(), AuthFailure> {
        if identity.account_id == self.account { Ok(()) } else { Err(Self::denied()) }
    }

    async fn authenticate_notification(
        &self,
        _method: &Method,
        uri: &Uri,
        credentials: &api::SyncNotificationAuth,
    ) -> Result<AuthenticatedNotification, AuthFailure> {
        if uri.path() == "/sync/v1/notify" && credentials.access_token == "bm90aWZ5.dGVzdA.dG9rZW4"
        {
            Ok(AuthenticatedNotification {
                identity: AuthenticatedDevice { device_id: self.device, account_id: self.account },
                expires_at: 4_102_444_800,
            })
        } else {
            Err(AuthFailure::new(
                StatusCode::UNAUTHORIZED,
                "auth.authentication_required",
                "Authentication required",
                "The notification credential must bind this endpoint.",
                false,
            )
            .expect("valid notification auth failure"))
        }
    }
}

fn request(method: Method, uri: &str, body: Vec<u8>) -> Request<Body> {
    let proof = format!("{method} {uri}");
    Request::builder()
        .method(method)
        .uri(uri)
        .header(header::AUTHORIZATION, "DPoP test-token")
        .header("dpop", proof)
        .header(header::CONTENT_TYPE, "application/cbor")
        .body(Body::from(body))
        .expect("valid test request")
}

async fn send(app: &Router, method: Method, uri: &str, body: Vec<u8>) -> Response {
    app.clone().oneshot(request(method, uri, body)).await.expect("router response")
}

async fn bytes(response: Response) -> Vec<u8> {
    to_bytes(response.into_body(), MAX_REQUEST_BYTES).await.expect("bounded response").to_vec()
}

async fn assert_problem(response: Response, status: StatusCode, code: &str) {
    assert_eq!(response.status(), status);
    let problem = ProblemDetails::from_cbor(&bytes(response).await).expect("CBOR problem");
    assert_eq!(problem.code.as_str(), code);
    assert!(!problem.changed);
}

async fn store() -> Arc<PostgresStore> {
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    Arc::new(PostgresStore::connect(&url).await.expect("connect PostgreSQL 17"))
}

async fn fanout(
    store: Arc<PostgresStore>,
    mut auth: TestAuthenticator,
    hub: NotificationHub,
    vault: Uuid,
) -> tokio::task::JoinHandle<Result<(), storage::SyncStoreError>> {
    auth.vault = Some(vault.into_bytes());
    let worker =
        scoplen_sync::notification_fanout::PostgresNotificationFanout::connect(store, auth, hub)
            .await
            .expect("prepared LISTEN");
    tokio::spawn(worker.run())
}

struct LostCommitProxy {
    database_url: String,
    armed: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LostCommitProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl LostCommitProxy {
    async fn start() -> Self {
        let database_url = std::env::var("SCOPLEN_TEST_DATABASE_URL").expect("PostgreSQL URL");
        let mut url = url::Url::parse(&database_url).expect("TCP PostgreSQL URL");
        let upstream = format!("{}:{}", url.host_str().expect("host"), url.port().unwrap_or(5432));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy listener");
        url.set_host(Some("127.0.0.1")).expect("proxy host");
        url.set_port(Some(listener.local_addr().expect("address").port())).expect("proxy port");
        url.set_query(Some("sslmode=disable"));
        let armed = Arc::new(AtomicBool::new(false));
        let dropped = Arc::new(AtomicUsize::new(0));
        let task = {
            let armed = armed.clone();
            let dropped = dropped.clone();
            tokio::spawn(async move {
                let mut connections = tokio::task::JoinSet::new();
                loop {
                    let (client, _) = listener.accept().await.expect("proxy client");
                    let server =
                        TcpStream::connect(&upstream).await.expect("PostgreSQL connection");
                    let armed = armed.clone();
                    let dropped = dropped.clone();
                    connections.spawn(async move {
                        Box::pin(drop_commit_ack(client, server, armed, dropped)).await;
                    });
                }
            })
        };
        Self { database_url: url.to_string(), armed, dropped, task }
    }
}

async fn drop_commit_ack(
    client: TcpStream,
    server: TcpStream,
    armed: Arc<AtomicBool>,
    dropped: Arc<AtomicUsize>,
) {
    let (mut client_read, mut client_write) = client.into_split();
    let (mut server_read, mut server_write) = server.into_split();
    let commit_forwarded = Arc::new(AtomicBool::new(false));
    let forwarding = {
        let commit_forwarded = commit_forwarded.clone();
        async move {
            let mut buffer = [0; 16_384];
            let mut tail = Vec::new();
            loop {
                let count = client_read.read(&mut buffer).await?;
                if count == 0 {
                    break;
                }
                tail.extend_from_slice(&buffer[..count]);
                if tail.windows(7).any(|bytes| bytes == b"COMMIT\0")
                    && armed.swap(false, Ordering::SeqCst)
                {
                    commit_forwarded.store(true, Ordering::SeqCst);
                }
                tail = tail[tail.len().saturating_sub(6)..].to_vec();
                server_write.write_all(&buffer[..count]).await?;
            }
            Ok::<(), std::io::Error>(())
        }
    };
    let returning = async move {
        let mut buffer = [0; 16_384];
        let mut withheld = Vec::new();
        loop {
            let count = server_read.read(&mut buffer).await?;
            if count == 0 {
                break;
            }
            if commit_forwarded.load(Ordering::SeqCst) {
                withheld.extend_from_slice(&buffer[..count]);
                if withheld.windows(7).any(|bytes| bytes == b"COMMIT\0") {
                    dropped.fetch_add(1, Ordering::SeqCst);
                    break;
                }
                if withheld.len() > 65_536 {
                    return Err(std::io::Error::other("commit reply exceeds test bound"));
                }
            } else {
                client_write.write_all(&buffer[..count]).await?;
            }
        }
        Ok::<(), std::io::Error>(())
    };
    let _ = tokio::select! { result = forwarding => result, result = returning => result };
}

async fn assert_storage_outcome(response: Response, changed: bool) {
    assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
    let problem = ProblemDetails::from_cbor(&bytes(response).await).expect("CBOR problem");
    assert_eq!(problem.code.as_str(), "sync.storage_unavailable");
    assert_eq!(problem.changed, changed);
    assert_eq!(problem.retryable, !changed);
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_router_preserves_lost_commit_outcomes_and_ack_no_ops() {
    let direct = store().await;
    let vault = Uuid::now_v7();
    let account = Uuid::now_v7();
    let device = Uuid::now_v7();
    direct
        .create_personal_sync_vault(vault.into_bytes(), account.into_bytes(), &[1])
        .await
        .expect("Personal vault");
    let mut committed_hints =
        direct.listen_sync_notifications().await.expect("independent committed-state listener");
    let proxy = LostCommitProxy::start().await;
    let proxied =
        Arc::new(PostgresStore::connect(&proxy.database_url).await.expect("proxied store"));
    let app = router_with_notifications(
        proxied.clone(),
        TestAuthenticator {
            account: account.into_bytes(),
            device: device.into_bytes(),
            vault_access: true,
            vault: None,
        },
        NotificationHub::default(),
    );
    let object = Uuid::now_v7();
    let batch = api::SyncWriteBatch {
        writes: vec![api::SyncWrite {
            object_id: object,
            base_seq: None,
            payload: vec![1],
            tombstone: false,
        }],
    };
    let write_uri = format!("/sync/v1/vaults/{vault}/objects");
    proxy.armed.store(true, Ordering::SeqCst);
    let response = tokio::time::timeout(
        Duration::from_secs(5),
        send(&app, Method::POST, &write_uri, batch.to_cbor().expect("write")),
    )
    .await
    .expect("lost write reply timeout");
    assert_storage_outcome(response, true).await;
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 1);
    let versions =
        direct.sync_versions(vault.into_bytes(), object.into_bytes()).await.expect("readback");
    assert_eq!(versions.len(), 1);
    assert_eq!(versions[0].sequence, 1, "the write committed despite its error response");
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            if let scoplen_store::sync_notifications::SyncNotificationMessage::Event(
                api::SyncNotification::VaultAdvanced { vault: seen, seq },
            ) = committed_hints.recv().await.expect("committed hint")
                && seen == vault
            {
                assert_eq!(seq, 1);
                break;
            }
        }
    })
    .await
    .expect("committed hint despite lost HTTP acknowledgement");

    let suffix = Uuid::new_v4().simple().to_string();
    let function = format!("fail_sync_{suffix}");
    let trigger = format!("fail_sync_trigger_{suffix}");
    let vault_hex = vault.simple().to_string();
    sqlx::raw_sql(&format!(
        "CREATE FUNCTION {function}() RETURNS trigger LANGUAGE plpgsql AS $$
         BEGIN IF NEW.vault_id = decode('{vault_hex}', 'hex') THEN
           RAISE EXCEPTION 'injected precommit sync failure';
         END IF; RETURN NEW; END $$;
         CREATE TRIGGER {trigger} BEFORE UPDATE ON sync_vaults
         FOR EACH ROW EXECUTE FUNCTION {function}();"
    ))
    .execute(direct.pool())
    .await
    .expect("precommit fixture");
    let update = api::SyncWriteBatch {
        writes: vec![api::SyncWrite {
            base_seq: Some(1),
            payload: vec![2],
            ..batch.writes[0].clone()
        }],
    };
    assert_storage_outcome(
        send(&app, Method::POST, &write_uri, update.to_cbor().expect("update")).await,
        false,
    )
    .await;
    sqlx::raw_sql(&format!("DROP TRIGGER {trigger} ON sync_vaults; DROP FUNCTION {function}();"))
        .execute(direct.pool())
        .await
        .expect("remove precommit fixture");
    assert_eq!(
        direct
            .sync_versions(vault.into_bytes(), object.into_bytes())
            .await
            .expect("rollback readback")
            .len(),
        1
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(100), async {
            loop {
                if let scoplen_store::sync_notifications::SyncNotificationMessage::Event(
                    api::SyncNotification::VaultAdvanced { vault: seen, .. },
                ) = committed_hints.recv().await.expect("listen")
                    && seen == vault
                {
                    break;
                }
            }
        })
        .await
        .is_err(),
        "rolled back writes emit no hint"
    );

    let ack_uri = format!("/sync/v1/vaults/{vault}/ack");
    for (cursor, changed) in [(1, true), (0, false)] {
        proxy.armed.store(true, Ordering::SeqCst);
        let response = tokio::time::timeout(
            Duration::from_secs(5),
            send(
                &app,
                Method::POST,
                &ack_uri,
                api::SyncAckRequest { cursor }.to_cbor().expect("ACK"),
            ),
        )
        .await
        .expect("lost ACK reply timeout");
        assert_storage_outcome(response, changed).await;
    }
    assert_eq!(proxy.dropped.load(Ordering::SeqCst), 3);
    assert_eq!(
        direct
            .ack_sync_cursor(vault.into_bytes(), device.into_bytes(), 0)
            .await
            .expect("ACK readback"),
        1
    );
    let response = send(
        &app,
        Method::POST,
        &ack_uri,
        api::SyncAckRequest { cursor: 0 }.to_cbor().expect("ACK"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        api::SyncAckResponse::from_cbor(&bytes(response).await).expect("ACK response").cursor,
        1
    );
    proxied.pool().close().await;
    drop(committed_hints);
    direct.pool().close().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_router_personal_sync_and_keys_round_trip() {
    let store = store().await;
    let account = Uuid::now_v7();
    let outsider_account = Uuid::now_v7();
    let device = Uuid::now_v7();
    let outsider_device = Uuid::now_v7();
    let vault = Uuid::now_v7();
    let outsider_vault = Uuid::now_v7();
    store
        .create_personal_sync_vault(vault.into_bytes(), account.into_bytes(), &[7, 8])
        .await
        .expect("owner vault");
    store
        .create_personal_sync_vault(
            outsider_vault.into_bytes(),
            outsider_account.into_bytes(),
            &[9],
        )
        .await
        .expect("outsider vault");
    let hub = NotificationHub::default();
    let mut notifications = hub.subscribe(AuthenticatedDevice {
        device_id: device.into_bytes(),
        account_id: account.into_bytes(),
    });
    let owner = TestAuthenticator {
        account: account.into_bytes(),
        device: device.into_bytes(),
        vault_access: true,
        vault: None,
    };
    let worker = fanout(store.clone(), owner.clone(), hub.clone(), vault).await;
    let app = router_with_notifications(store.clone(), owner.clone(), hub);
    let outsider = router_with_notifications(
        store.clone(),
        TestAuthenticator {
            account: outsider_account.into_bytes(),
            device: outsider_device.into_bytes(),
            vault_access: true,
            vault: None,
        },
        NotificationHub::default(),
    );

    let session = api::SyncSessionRequest {
        client_version: env!("CARGO_PKG_VERSION").into(),
        model_version: CURRENT_SCHEMA_VERSION,
        device_id: device,
    };
    let response =
        send(&app, Method::POST, "/sync/v1/session", session.to_cbor().expect("session")).await;
    assert_eq!(response.status(), StatusCode::OK);
    let listing =
        api::SyncSessionResponse::from_cbor(&bytes(response).await).expect("session CBOR");
    assert_eq!(listing.vaults.len(), 1);
    assert_eq!(listing.vaults[0].id, vault);
    assert_eq!(
        listing.limits.max_objects_per_vault,
        store.sync_cardinality_limits().max_objects_per_vault
    );

    let owner_key_uri = format!("/sync/v1/vaults/{vault}/keys");
    let response = send(&app, Method::GET, &owner_key_uri, vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let key = api::SyncVaultKeysResponse::from_cbor(&bytes(response).await).expect("vault key");
    assert_eq!(key.keys[0].wrapped_vault_key, vec![7, 8]);
    assert_problem(
        send(&outsider, Method::GET, &owner_key_uri, vec![]).await,
        StatusCode::NOT_FOUND,
        "sync.object_not_found",
    )
    .await;

    let wrong_proof = Request::builder()
        .method(Method::GET)
        .uri(&owner_key_uri)
        .header(header::AUTHORIZATION, "DPoP test-token")
        .header("dpop", "GET /sync/v1/keys")
        .body(Body::empty())
        .expect("wrong proof request");
    assert_problem(
        app.clone().oneshot(wrong_proof).await.expect("wrong proof response"),
        StatusCode::UNAUTHORIZED,
        "auth.authentication_required",
    )
    .await;

    let update = api::SyncAccountKeyBundleUpdate {
        revision: 1,
        device_wraps: vec![api::SyncAccountDeviceWrap {
            device_id: device,
            wrapped_ark: vec![1, 2],
        }],
        account_signing_key: vec![3],
        account_kem_key: vec![4],
        recovery_blob: vec![5],
        signature: vec![6; api::SYNC_KEY_SIGNATURE_BYTES],
    };
    let update_body = update.to_cbor().expect("account key update");
    for _ in 0..2 {
        let response = send(&app, Method::PUT, "/sync/v1/keys", update_body.clone()).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            api::SyncAccountKeyBundlePutResponse::from_cbor(&bytes(response).await)
                .expect("key PUT response")
                .revision,
            1
        );
    }
    let response = send(&app, Method::GET, "/sync/v1/keys", vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let bundle = api::SyncAccountKeyBundle::from_cbor(&bytes(response).await).expect("key GET");
    assert_eq!(bundle.wrapped_ark, vec![1, 2]);
    assert_problem(
        send(&outsider, Method::GET, "/sync/v1/keys", vec![]).await,
        StatusCode::NOT_FOUND,
        "sync.object_not_found",
    )
    .await;
    let mut conflicting_update = update;
    conflicting_update.account_kem_key = vec![99];
    assert_problem(
        send(
            &app,
            Method::PUT,
            "/sync/v1/keys",
            conflicting_update.to_cbor().expect("changed update"),
        )
        .await,
        StatusCode::CONFLICT,
        "sync.conflict",
    )
    .await;

    let object = Uuid::now_v7();
    let write_uri = format!("/sync/v1/vaults/{vault}/objects");
    let batch = api::SyncWriteBatch {
        writes: vec![api::SyncWrite {
            object_id: object,
            base_seq: None,
            payload: vec![10],
            tombstone: false,
        }],
    };
    let batch_body = batch.to_cbor().expect("write batch");
    let response = send(&app, Method::POST, &write_uri, batch_body.clone()).await;
    assert_eq!(response.status(), StatusCode::OK);
    let receipt = api::SyncWriteBatchResponse::from_cbor(&bytes(response).await).expect("receipt");
    assert_eq!(receipt.assignments[0].seq, 1);
    assert_eq!(
        api::SyncNotification::from_cbor(
            &tokio::time::timeout(Duration::from_secs(5), notifications.recv())
                .await
                .expect("delivery bound")
                .expect("committed notification")
        )
        .expect("notification CBOR"),
        api::SyncNotification::VaultAdvanced { vault, seq: 1 }
    );
    assert_eq!(
        send(&app, Method::POST, &write_uri, batch_body).await.status(),
        StatusCode::CONFLICT
    );
    assert!(notifications.try_recv().is_err());

    let changes_uri = format!("/sync/v1/vaults/{vault}/changes?after=0&limit=10");
    let response = send(&app, Method::GET, &changes_uri, vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let changes = api::SyncChangesResponse::from_cbor(&bytes(response).await).expect("changes");
    assert_eq!(changes.changes[0].object_id, object);
    let snapshot_uri = format!("/sync/v1/vaults/{vault}/snapshot?after=0&limit=10");
    let response = send(&app, Method::GET, &snapshot_uri, vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        api::SyncSnapshotResponse::from_cbor(&bytes(response).await)
            .expect("snapshot")
            .objects
            .len(),
        1
    );
    let versions_uri = format!("/sync/v1/vaults/{vault}/objects/{object}/versions");
    let response = send(&app, Method::GET, &versions_uri, vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        api::SyncVersionsResponse::from_cbor(&bytes(response).await)
            .expect("versions")
            .versions
            .len(),
        1
    );
    let ack_uri = format!("/sync/v1/vaults/{vault}/ack");
    let response = send(
        &app,
        Method::POST,
        &ack_uri,
        api::SyncAckRequest { cursor: 1 }.to_cbor().expect("ack"),
    )
    .await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        api::SyncAckResponse::from_cbor(&bytes(response).await).expect("ack CBOR").cursor,
        1
    );
    assert_problem(
        send(
            &app,
            Method::POST,
            &ack_uri,
            api::SyncAckRequest { cursor: 2 }.to_cbor().expect("ahead ack"),
        )
        .await,
        StatusCode::BAD_REQUEST,
        "sync.cursor_ahead",
    )
    .await;
    worker.abort();
    let _ = worker.await;
    store.pool().close().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_router_shared_vault_mutations_and_membership() {
    let url = std::env::var("SCOPLEN_TEST_DATABASE_URL")
        .expect("SCOPLEN_TEST_DATABASE_URL is required for PostgreSQL integration tests");
    let limits =
        storage::SyncCardinalityLimits { max_shared_vaults_per_account: 1, ..Default::default() };
    let store = Arc::new(
        PostgresStore::connect_with_sync_limits(&url, limits)
            .await
            .expect("connect PostgreSQL 17 with quota"),
    );
    let account = Uuid::now_v7();
    let member = Uuid::now_v7();
    let device = Uuid::now_v7();
    let vault = Uuid::now_v7();
    let hub = NotificationHub::default();
    let mut notifications = hub.subscribe(AuthenticatedDevice {
        device_id: device.into_bytes(),
        account_id: account.into_bytes(),
    });
    let auth = TestAuthenticator {
        account: account.into_bytes(),
        device: device.into_bytes(),
        vault_access: true,
        vault: None,
    };
    let worker = fanout(store.clone(), auth.clone(), hub.clone(), vault).await;
    let app = router_with_notifications(store.clone(), auth, hub);
    let create = api::SyncCreateVaultRequest { vault_id: vault, wrapped_vault_key: vec![1] };
    let response =
        send(&app, Method::POST, "/sync/v1/vaults", create.to_cbor().expect("create")).await;
    assert_eq!(response.status(), StatusCode::OK);
    assert_eq!(
        api::SyncCreateVaultResponse::from_cbor(&bytes(response).await).expect("created").vault.id,
        vault
    );
    assert_problem(
        send(&app, Method::POST, "/sync/v1/vaults", create.to_cbor().expect("duplicate")).await,
        StatusCode::CONFLICT,
        "sync.conflict",
    )
    .await;
    let over_quota =
        api::SyncCreateVaultRequest { vault_id: Uuid::now_v7(), wrapped_vault_key: vec![9] };
    assert_problem(
        send(&app, Method::POST, "/sync/v1/vaults", over_quota.to_cbor().expect("quota request"))
            .await,
        StatusCode::PAYLOAD_TOO_LARGE,
        "sync.quota_exceeded",
    )
    .await;

    let epoch_uri = format!("/sync/v1/vaults/{vault}/epochs");
    let epoch = api::SyncPublishVaultEpochRequest {
        epoch: 2,
        wrapped_keys: vec![api::SyncVaultEpochWrap {
            account_id: account,
            wrapped_vault_key: vec![2],
        }],
    };
    assert_eq!(
        send(&app, Method::POST, &epoch_uri, epoch.to_cbor().expect("epoch")).await.status(),
        StatusCode::OK
    );
    let add_uri = format!("/sync/v1/vaults/{vault}/members");
    let add = api::SyncAddVaultMemberRequest {
        account_id: member,
        wrapped_keys: vec![
            api::SyncVaultKey { epoch: 1, wrapped_vault_key: vec![3] },
            api::SyncVaultKey { epoch: 2, wrapped_vault_key: vec![4] },
        ],
    };
    assert_eq!(
        send(&app, Method::POST, &add_uri, add.to_cbor().expect("add member")).await.status(),
        StatusCode::OK
    );
    let member_app = router_with_notifications(
        store.clone(),
        TestAuthenticator {
            account: member.into_bytes(),
            device: Uuid::now_v7().into_bytes(),
            vault_access: true,
            vault: None,
        },
        NotificationHub::default(),
    );
    let keys_uri = format!("/sync/v1/vaults/{vault}/keys");
    let response = send(&member_app, Method::GET, &keys_uri, vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let member_keys =
        api::SyncVaultKeysResponse::from_cbor(&bytes(response).await).expect("member keys");
    assert_eq!(member_keys.keys.len(), 2);
    assert_eq!(member_keys.keys[1].wrapped_vault_key, vec![4]);

    let remove_uri = format!("/sync/v1/vaults/{vault}/members/{member}");
    assert_eq!(send(&app, Method::DELETE, &remove_uri, vec![]).await.status(), StatusCode::OK);
    assert_eq!(
        api::SyncNotification::from_cbor(
            &tokio::time::timeout(Duration::from_secs(5), notifications.recv())
                .await
                .expect("delivery bound")
                .expect("rotation notification")
        )
        .expect("notification CBOR"),
        api::SyncNotification::RotationPending { vault }
    );
    assert_problem(
        send(&member_app, Method::GET, &keys_uri, vec![]).await,
        StatusCode::NOT_FOUND,
        "sync.object_not_found",
    )
    .await;
    let retire_uri = format!("/sync/v1/vaults/{vault}/epochs/1/retire");
    assert_eq!(send(&app, Method::POST, &retire_uri, vec![]).await.status(), StatusCode::OK);
    let response = send(&app, Method::GET, &keys_uri, vec![]).await;
    assert_eq!(response.status(), StatusCode::OK);
    let owner_keys =
        api::SyncVaultKeysResponse::from_cbor(&bytes(response).await).expect("owner keys");
    assert_eq!(owner_keys.keys.len(), 1);
    assert_eq!(owner_keys.keys[0].epoch, 2);
    assert_problem(
        send(
            &router_with_notifications(
                store.clone(),
                TestAuthenticator {
                    account: account.into_bytes(),
                    device: device.into_bytes(),
                    vault_access: false,
                    vault: None,
                },
                NotificationHub::default(),
            ),
            Method::GET,
            &keys_uri,
            vec![],
        )
        .await,
        StatusCode::FORBIDDEN,
        "policy.denied",
    )
    .await;
    worker.abort();
    let _ = worker.await;
    store.pool().close().await;
}

#[tokio::test]
#[allow(clippy::too_many_lines)]
async fn postgres_router_notification_socket_authenticates_and_receives_committed_write() {
    let store = store().await;
    let account = Uuid::now_v7();
    let device = Uuid::now_v7();
    let vault = Uuid::now_v7();
    store
        .create_personal_sync_vault(vault.into_bytes(), account.into_bytes(), &[1])
        .await
        .expect("notification vault");
    let hub = NotificationHub::default();
    let worker = fanout(
        store.clone(),
        TestAuthenticator {
            account: account.into_bytes(),
            device: device.into_bytes(),
            vault_access: true,
            vault: None,
        },
        hub.clone(),
        vault,
    )
    .await;
    let app = router_with_notifications(
        store.clone(),
        TestAuthenticator {
            account: account.into_bytes(),
            device: device.into_bytes(),
            vault_access: true,
            vault: None,
        },
        hub.clone(),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("bind notification listener");
    let address = listener.local_addr().expect("notification listener address");
    let server = tokio::spawn({
        let app = app.clone();
        async move { axum::serve(listener, app).await.expect("serve notification router") }
    });

    let (mut invalid_socket, _) = connect_async(format!("ws://{address}/sync/v1/notify"))
        .await
        .expect("invalid notification socket");
    let ClientMessage::Binary(context) =
        invalid_socket.next().await.expect("context").expect("context frame")
    else {
        panic!("binary context")
    };
    api::SyncNotificationContext::from_cbor(&context).expect("context codec");
    invalid_socket
        .send(ClientMessage::Binary(b"invalid".to_vec().into()))
        .await
        .expect("send invalid credential");
    let close = tokio::time::timeout(Duration::from_secs(5), invalid_socket.next())
        .await
        .expect("invalid socket timeout")
        .expect("invalid socket response")
        .expect("invalid socket frame");
    let ClientMessage::Close(Some(frame)) = close else {
        panic!("invalid notification credential did not close the socket");
    };
    assert_eq!(frame.reason, "auth.authentication_required");
    let identity =
        AuthenticatedDevice { device_id: device.into_bytes(), account_id: account.into_bytes() };
    assert_eq!(hub.receiver_count(identity), 0);

    let (mut socket, _) =
        connect_async(format!("ws://{address}/sync/v1/notify")).await.expect("notification socket");
    let ClientMessage::Binary(context) =
        socket.next().await.expect("context").expect("context frame")
    else {
        panic!("binary context")
    };
    api::SyncNotificationContext::from_cbor(&context).expect("context codec");
    socket
        .send(ClientMessage::Binary(
            api::SyncNotificationAuth {
                access_token: "bm90aWZ5.dGVzdA.dG9rZW4".into(),
                dpop_proof: "ZA.ZQ.Zg".into(),
            }
            .to_cbor()
            .expect("D75 authentication")
            .into(),
        ))
        .await
        .expect("send notification credential");
    let ClientMessage::Binary(ready) = socket.next().await.expect("ready").expect("ready frame")
    else {
        panic!("binary ready")
    };
    api::SyncNotificationReady::from_cbor(&ready).expect("ready codec");
    tokio::time::timeout(Duration::from_secs(5), async {
        while hub.receiver_count(identity) != 1 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("notification subscription timeout");

    let batch = api::SyncWriteBatch {
        writes: vec![api::SyncWrite {
            object_id: Uuid::now_v7(),
            base_seq: None,
            payload: vec![10],
            tombstone: false,
        }],
    };
    let uri = format!("/sync/v1/vaults/{vault}/objects");
    assert_eq!(
        send(&app, Method::POST, &uri, batch.to_cbor().expect("write batch")).await.status(),
        StatusCode::OK
    );
    let message = tokio::time::timeout(Duration::from_secs(5), socket.next())
        .await
        .expect("notification delivery timeout")
        .expect("notification socket response")
        .expect("notification socket frame");
    let ClientMessage::Binary(payload) = message else {
        panic!("committed write did not send a binary notification");
    };
    assert_eq!(
        api::SyncNotification::from_cbor(&payload).expect("notification CBOR"),
        api::SyncNotification::VaultAdvanced { vault, seq: 1 }
    );
    socket.close(None).await.expect("close notification socket");
    server.abort();
    assert!(server.await.expect_err("notification server must stop").is_cancelled());
    worker.abort();
    let _ = worker.await;
    store.pool().close().await;
}
