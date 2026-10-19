// SPDX-License-Identifier: AGPL-3.0-only
#![cfg(feature = "postgres-integration")]

use std::{sync::Arc, time::Duration};

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
        AuthFailure, AuthenticatedDevice, MAX_REQUEST_BYTES, SyncAuthenticator, SyncKeysOperation,
        SyncOperation, router_with_notifications,
    },
    notify::NotificationHub,
};
use tokio::net::TcpListener;
use tokio_tungstenite::{connect_async, tungstenite::Message as ClientMessage};
use tower::ServiceExt;
use uuid::Uuid;

#[derive(Clone)]
struct TestAuthenticator {
    account: keys::AccountId,
    device: storage::DeviceId,
    vault_access: bool,
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

impl SyncAuthenticator for TestAuthenticator {
    fn authenticate(
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
        Ok(AuthenticatedDevice { device_id: self.device })
    }

    fn authorize(
        &self,
        _identity: AuthenticatedDevice,
        _vault: storage::VaultId,
        _operation: SyncOperation,
    ) -> Result<(), AuthFailure> {
        if self.vault_access { Ok(()) } else { Err(Self::denied()) }
    }

    fn validate_write(
        &self,
        _identity: AuthenticatedDevice,
        _vault: storage::VaultId,
        writes: &[api::SyncWrite],
    ) -> Result<Vec<u64>, AuthFailure> {
        Ok(vec![1; writes.len()])
    }

    fn account_id(&self, _identity: AuthenticatedDevice) -> Result<keys::AccountId, AuthFailure> {
        Ok(self.account)
    }

    fn authorize_session(&self, _identity: AuthenticatedDevice) -> Result<(), AuthFailure> {
        Ok(())
    }

    fn authorize_keys(
        &self,
        _identity: AuthenticatedDevice,
        _account_id: keys::AccountId,
        _operation: SyncKeysOperation,
    ) -> Result<(), AuthFailure> {
        Ok(())
    }

    fn validate_key_bundle_update(
        &self,
        _identity: AuthenticatedDevice,
        _account_id: keys::AccountId,
        _update: &api::SyncAccountKeyBundleUpdate,
    ) -> Result<(), AuthFailure> {
        Ok(())
    }

    fn authorize_notifications(&self, _identity: AuthenticatedDevice) -> Result<(), AuthFailure> {
        Ok(())
    }

    fn authenticate_notification(
        &self,
        uri: &Uri,
        first_message: &[u8],
    ) -> Result<AuthenticatedDevice, AuthFailure> {
        if uri.path() == "/sync/v1/notify" && first_message == b"notify-test-token" {
            Ok(AuthenticatedDevice { device_id: self.device })
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
    let mut notifications = hub.subscribe(device.into_bytes());
    let owner = TestAuthenticator {
        account: account.into_bytes(),
        device: device.into_bytes(),
        vault_access: true,
    };
    let app = router_with_notifications(store.clone(), owner.clone(), hub);
    let outsider = router_with_notifications(
        store.clone(),
        TestAuthenticator {
            account: outsider_account.into_bytes(),
            device: outsider_device.into_bytes(),
            vault_access: true,
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
            &notifications.try_recv().expect("committed notification")
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
    let mut notifications = hub.subscribe(device.into_bytes());
    let app = router_with_notifications(
        store.clone(),
        TestAuthenticator {
            account: account.into_bytes(),
            device: device.into_bytes(),
            vault_access: true,
        },
        hub,
    );
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
        api::SyncNotification::from_cbor(&notifications.try_recv().expect("rotation notification"))
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
    store.pool().close().await;
}

#[tokio::test]
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
    let app = router_with_notifications(
        store.clone(),
        TestAuthenticator {
            account: account.into_bytes(),
            device: device.into_bytes(),
            vault_access: true,
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
    invalid_socket
        .send(ClientMessage::Binary(b"invalid".to_vec().into()))
        .await
        .expect("send invalid credential");
    let close = tokio::time::timeout(Duration::from_secs(1), invalid_socket.next())
        .await
        .expect("invalid socket timeout")
        .expect("invalid socket response")
        .expect("invalid socket frame");
    let ClientMessage::Close(Some(frame)) = close else {
        panic!("invalid notification credential did not close the socket");
    };
    assert_eq!(frame.reason, "auth.authentication_required");
    assert_eq!(hub.receiver_count(device.into_bytes()), 0);

    let (mut socket, _) =
        connect_async(format!("ws://{address}/sync/v1/notify")).await.expect("notification socket");
    socket
        .send(ClientMessage::Binary(b"notify-test-token".to_vec().into()))
        .await
        .expect("send notification credential");
    for _ in 0..100 {
        if hub.receiver_count(device.into_bytes()) == 1 {
            break;
        }
        tokio::time::sleep(Duration::from_millis(1)).await;
    }
    assert_eq!(hub.receiver_count(device.into_bytes()), 1);

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
    let message = tokio::time::timeout(Duration::from_secs(1), socket.next())
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
    store.pool().close().await;
}
