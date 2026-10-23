// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use axum::{
    Extension,
    body::Body,
    extract::ConnectInfo,
    http::{Method, Request},
};
use futures_util::{SinkExt as _, StreamExt as _};
use hyper_util::rt::{TokioExecutor, TokioIo};
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use scoplen_api::sync::{
    SyncNotification, SyncNotificationAuth, SyncNotificationContext, SyncNotificationMethod,
    SyncNotificationReady,
};
use scoplen_crypto::{DeviceAccessToken, DeviceAccessTokenClaims, TrustedDeviceAccessTokenKeys};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::TcpStream,
};
use tokio_rustls::{TlsAcceptor, TlsConnector};
use tokio_tungstenite::{
    WebSocketStream, client_async,
    tungstenite::{Message, protocol::Role},
};

const PATH: &str = "/sync/v1/notify";
type Socket = WebSocketStream<tokio_rustls::client::TlsStream<TcpStream>>;

struct Listener {
    address: SocketAddr,
    roots: RootCertStore,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for Listener {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl Listener {
    async fn start(f: &mut Fixture) -> Self {
        f.server.abort();
        let _ = (&mut f.server).await;
        let storage = ObjectStorage::from_config(&ObjectStorageConfig::Filesystem {
            root: f.directory.join("objects"),
        })
        .expect("storage");
        let kms = LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS");
        let database = match &f.backend {
            AuthBackend::Sqlite(store) => ListenerDatabase::Sqlite(store.clone()),
            AuthBackend::Postgres(store) => ListenerDatabase::Postgres(store.clone()),
        };
        let app = api_router(database, Arc::new(storage), Arc::new(kms), ORIGIN.into(), true);
        let plain = TcpListener::bind("127.0.0.1:0").await.expect("HTTP listener");
        f.address = plain.local_addr().expect("HTTP address");
        let plain_app = app.clone();
        f.server = tokio::spawn(async move {
            axum::serve(plain, plain_app.into_make_service_with_connect_info::<SocketAddr>())
                .await
                .expect("HTTP API");
        });
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["setup.example.com".into()])
                .expect("owned TLS certificate");
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .expect("TLS config");
        config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).expect("test-only TLS root");
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("TLS listener");
        let address = listener.local_addr().expect("TLS address");
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    accepted = listener.accept() => {
                        let (tcp, peer) = accepted.expect("TLS accept");
                        let acceptor = acceptor.clone();
                        let app = app.clone().layer(Extension(ConnectInfo(peer)));
                        connections.spawn(async move {
                            let tls = acceptor.accept(tcp).await.expect("TLS handshake");
                            let _ = crate::runtime::serve_tls_io(tls, app, false).await;
                        });
                    }
                    Some(result) = connections.join_next() => { result.expect("TLS task"); }
                }
            }
        });
        Self { address, roots, task }
    }

    async fn tls(&self, protocol: &[u8]) -> tokio_rustls::client::TlsStream<TcpStream> {
        let mut config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .expect("TLS versions")
        .with_root_certificates(self.roots.clone())
        .with_no_client_auth();
        config.alpn_protocols = vec![protocol.to_vec()];
        let tls = TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::try_from("setup.example.com").expect("SNI"),
                TcpStream::connect(self.address).await.expect("TLS TCP"),
            )
            .await
            .expect("verified TLS");
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(protocol));
        tls
    }

    async fn get(&self) -> Socket {
        let tls = self.tls(b"http/1.1").await;
        let (mut socket, response) =
            client_async(format!("wss://setup.example.com:9443{PATH}"), tls)
                .await
                .expect("WebSocket upgrade");
        assert_eq!(response.status(), 101);
        context(&mut socket, SyncNotificationMethod::Get).await;
        socket
    }

    async fn h2(
        &self,
    ) -> (WebSocketStream<TokioIo<hyper::upgrade::Upgraded>>, tokio::task::JoinHandle<()>) {
        let tls = self.tls(b"h2").await;
        let (mut sender, connection) =
            hyper::client::conn::http2::Builder::new(TokioExecutor::new())
                .handshake(TokioIo::new(tls))
                .await
                .expect("H2 handshake");
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        sender.ready().await.expect("H2 ready");
        let request = Request::builder()
            .method(Method::CONNECT)
            .uri(format!("{ORIGIN}{PATH}"))
            .extension(hyper::ext::Protocol::from_static("websocket"))
            .header("sec-websocket-version", "13")
            .body(Body::empty())
            .expect("CONNECT");
        let mut response = sender.send_request(request).await.expect("extended CONNECT");
        assert_eq!(response.status(), 200);
        let upgraded = hyper::upgrade::on(&mut response).await.expect("H2 tunnel");
        let mut socket =
            WebSocketStream::from_raw_socket(TokioIo::new(upgraded), Role::Client, None).await;
        context(&mut socket, SyncNotificationMethod::Connect).await;
        (socket, task)
    }
}

async fn next<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut WebSocketStream<S>) -> Message {
    tokio::time::timeout(Duration::from_secs(4), socket.next())
        .await
        .expect("bounded socket response")
        .expect("socket response")
        .expect("WebSocket frame")
}

async fn context<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
    method: SyncNotificationMethod,
) {
    let Message::Binary(body) = next(socket).await else { panic!("context must be binary") };
    assert_eq!(SyncNotificationContext::from_cbor(&body).expect("D75 context").htm, method);
}

fn credentials(
    key: &P256SigningKey,
    token: &str,
    method: &str,
    path: &str,
    proof_token: &str,
) -> Vec<u8> {
    let proof = DpopProof::sign(
        key,
        &key.public_key_sec1(),
        &DpopTarget::new(method, ORIGIN, path).expect("target"),
        DpopToken::Protected(proof_token),
        SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs(),
        None,
    )
    .expect("fresh proof");
    SyncNotificationAuth { access_token: token.into(), dpop_proof: proof.as_str().into() }
        .to_cbor()
        .expect("D75 credentials")
}

async fn ready<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut WebSocketStream<S>, body: &[u8]) {
    socket.send(Message::Binary(body.to_vec().into())).await.expect("authentication");
    let Message::Binary(body) = next(socket).await else { panic!("ready must be binary") };
    SyncNotificationReady::from_cbor(&body).expect("D75 ready");
}

async fn closed<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut WebSocketStream<S>, code: u16) {
    let Message::Close(Some(frame)) = next(socket).await else {
        panic!("fixed safe close without ready or event")
    };
    assert_eq!(u16::from(frame.code), code);
    assert!(
        frame.reason == "auth.authentication_required"
            || frame.reason.starts_with("sync.notification_")
    );
}

async fn no_event<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut WebSocketStream<S>) {
    assert!(
        tokio::time::timeout(Duration::from_millis(100), socket.next()).await.is_err(),
        "unauthorized or rejected writes emit no event"
    );
}

async fn paired(f: &Fixture, identity: &PersonalBootstrap) -> String {
    let created = pairing::create(f).await;
    let request = pairing::ready(f, identity, &created).await;
    let reply = protected(
        f,
        "POST",
        &format!("/api/v1/auth/pairings/{}/complete", created.context.pairing_id),
        &request.to_json().expect("approval"),
        &identity.token,
        &identity.client,
    )
    .await;
    assert_eq!(reply.status, 200);
    authenticate_device(f, created.context.responder_device_id, &key(4)).await
}

async fn another_account(f: &Fixture, identity: &PersonalBootstrap) -> (String, P256SigningKey) {
    let reply = protected(
        f,
        "POST",
        "/api/v1/admin/personal-invitations",
        b"{}",
        &identity.operator_token,
        &identity.operator_key,
    )
    .await;
    assert_eq!(reply.status, 201);
    let invitation = PersonalInvitationResponse::from_json(&reply.body).expect("invitation");
    let token = URL_SAFE_NO_PAD
        .decode(invitation.invitation_url.split("#token=").nth(1).expect("fragment"))
        .expect("token")
        .try_into()
        .expect("32 bytes");
    let client = key(6);
    let request = enrollment(token, &client);
    let reply = http(
        f.address,
        "/api/v1/auth/personal-enroll",
        &request.to_json().expect("enrollment"),
        &[("Content-Type", "application/json")],
    )
    .await;
    assert_eq!(reply.status, 201);
    (authenticate_device(f, request.device_certificate.device_id, &client).await, client)
}

async fn delivery(mut f: Fixture) {
    let identity = bootstrap_personal(&mut f).await;
    let second = paired(&f, &identity).await;
    let (foreign, foreign_key) = another_account(&f, &identity).await;
    let listener = Listener::start(&mut f).await;
    let mut first = listener.get().await;
    first.send(Message::Ping(vec![1].into())).await.expect("preauth ping");
    assert_eq!(next(&mut first).await, Message::Pong(vec![1].into()));
    ready(
        &mut first,
        &credentials(&identity.client, &identity.token, "GET", PATH, &identity.token),
    )
    .await;
    let (mut second_socket, h2_task) = listener.h2().await;
    ready(&mut second_socket, &credentials(&key(4), &second, "CONNECT", PATH, &second)).await;
    let mut unrelated = listener.get().await;
    ready(&mut unrelated, &credentials(&foreign_key, &foreign, "GET", PATH, &foreign)).await;
    sync_object(&f, &identity.receipt, &identity.token, &identity.client).await;
    for body in [next(&mut first).await, next(&mut second_socket).await] {
        let Message::Binary(body) = body else { panic!("content-free event") };
        assert_eq!(
            SyncNotification::from_cbor(&body).expect("event"),
            SyncNotification::VaultAdvanced { vault: identity.receipt.personal_vault_id, seq: 1 }
        );
    }
    no_event(&mut unrelated).await;
    let denied = protected(
        &f,
        "POST",
        &format!("/sync/v1/vaults/{}/objects", identity.receipt.personal_vault_id),
        &[0xa0],
        &identity.token,
        &identity.client,
    )
    .await;
    assert_eq!(denied.status, 400);
    no_event(&mut first).await;
    no_event(&mut second_socket).await;
    second_socket
        .send(Message::Binary(vec![0xa0].into()))
        .await
        .expect("unexpected application data");
    closed(&mut second_socket, 1008).await;
    drop(second_socket);
    h2_task.abort();
    f.execute("UPDATE identity_devices SET active=false").await;
    closed(&mut first, 1008).await;
    closed(&mut unrelated, 1008).await;
    drop((first, unrelated, listener));
    f.cleanup().await;
}

#[allow(clippy::too_many_lines)]
async fn denials(mut f: Fixture) {
    let identity = bootstrap_personal(&mut f).await;
    let missing_scope = account_profile::signed_token(
        &f,
        &identity,
        identity.receipt.account_id,
        identity.receipt.device_id,
        "keys:read",
    )
    .await;
    let wrong_account = account_profile::signed_token(
        &f,
        &identity,
        Uuid::now_v7(),
        identity.receipt.device_id,
        "sync:read",
    )
    .await;
    let listener = Listener::start(&mut f).await;
    for (token, signer, method, path, hash_token) in [
        (&identity.token, &identity.client, "CONNECT", PATH, &identity.token),
        (&identity.token, &identity.client, "GET", "/sync/v1/session", &identity.token),
        (&identity.token, &identity.client, "GET", PATH, &wrong_account),
        (&identity.token, &key(5), "GET", PATH, &identity.token),
        (&missing_scope, &identity.client, "GET", PATH, &missing_scope),
        (&wrong_account, &identity.client, "GET", PATH, &wrong_account),
        (&identity.operator_token, &identity.operator_key, "GET", PATH, &identity.operator_token),
    ] {
        let mut socket = listener.get().await;
        socket
            .send(Message::Binary(credentials(signer, token, method, path, hash_token).into()))
            .await
            .expect("invalid authentication");
        closed(&mut socket, 1008).await;
    }
    let proof = credentials(&identity.client, &identity.token, "GET", PATH, &identity.token);
    let mut accepted = listener.get().await;
    ready(&mut accepted, &proof).await;
    let mut replay = listener.get().await;
    replay.send(Message::Binary(proof.into())).await.expect("reused proof");
    closed(&mut replay, 1008).await;
    for message in [
        Message::Text("invalid".into()),
        Message::Binary(vec![0xa0].into()),
        Message::Binary(vec![0; 16_385].into()),
        Message::Text("x".repeat(16_385).into()),
    ] {
        let code = if message.len() > 16_384 {
            1009
        } else if message.is_text() {
            1003
        } else {
            1008
        };
        let mut socket = listener.get().await;
        socket.send(message).await.expect("invalid wire message");
        closed(&mut socket, code).await;
    }
    accepted.send(Message::Text("unexpected".into())).await.expect("postauth text");
    closed(&mut accepted, 1003).await;
    for message in
        [Message::Binary(vec![0; 16_385].into()), Message::Text("x".repeat(16_385).into())]
    {
        let mut socket = listener.get().await;
        ready(
            &mut socket,
            &credentials(&identity.client, &identity.token, "GET", PATH, &identity.token),
        )
        .await;
        socket.send(message).await.expect("postauth oversize message");
        closed(&mut socket, 1009).await;
    }
    // A mandatory replay claim failing before authentication must never produce ready.
    let failure = match &f.backend {
        AuthBackend::Sqlite(_) => {
            "CREATE TRIGGER fail_notify_replay BEFORE INSERT ON device_dpop_replays BEGIN SELECT RAISE(ABORT, 'unavailable'); END"
        }
        AuthBackend::Postgres(_) => {
            "CREATE FUNCTION fail_notify_replay() RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RAISE EXCEPTION 'unavailable'; END $$; CREATE TRIGGER fail_notify_replay BEFORE INSERT ON device_dpop_replays FOR EACH ROW EXECUTE FUNCTION fail_notify_replay()"
        }
    };
    f.execute(failure).await;
    let mut unavailable = listener.get().await;
    unavailable
        .send(Message::Binary(
            credentials(&identity.client, &identity.token, "GET", PATH, &identity.token).into(),
        ))
        .await
        .expect("temporary failure auth");
    closed(&mut unavailable, 1011).await;
    drop((accepted, replay, unavailable, listener));
    f.cleanup().await;
}

async fn signed_expiring_token(
    f: &Fixture,
    identity: &PersonalBootstrap,
    expires_at: u64,
) -> String {
    let kms = LocalKeyFile::load(f.directory.join("deployment.key")).expect("KMS");
    let keyring = f.backend.keyring(&kms).await.expect("signing keys");
    let mut trusted = TrustedDeviceAccessTokenKeys::new(ORIGIN).expect("issuer");
    for key in keyring.verification_keys() {
        trusted.insert(&key.kid, &key.public_key).expect("verification key");
    }
    let claims = DeviceAccessTokenClaims {
        iss: ORIGIN.into(),
        sub: identity.receipt.account_id,
        did: identity.receipt.device_id,
        jti: Uuid::now_v7(),
        cnf_jkt: dpop_jwk_thumbprint(&identity.client.public_key_sec1()).expect("JKT"),
        org: vec![],
        scope: "sync:read".into(),
        iat: expires_at - 600,
        exp: expires_at,
    };
    DeviceAccessToken::sign(
        keyring.signing_key(),
        &trusted,
        keyring.signing_key().kid(),
        &identity.client.public_key_sec1(),
        &claims,
    )
    .expect("expiring token")
    .as_str()
    .to_owned()
}

async fn expiry(mut f: Fixture) {
    let identity = bootstrap_personal(&mut f).await;
    let listener = Listener::start(&mut f).await;
    let mut socket = listener.get().await;
    let now = SystemTime::now().duration_since(UNIX_EPOCH).expect("clock").as_secs();
    let expiring = signed_expiring_token(&f, &identity, now + 3).await;
    let expired = signed_expiring_token(&f, &identity, now - 1).await;
    ready(&mut socket, &credentials(&identity.client, &expiring, "GET", PATH, &expiring)).await;
    closed(&mut socket, 1008).await;
    let mut rejected = listener.get().await;
    rejected
        .send(Message::Binary(
            credentials(&identity.client, &expired, "GET", PATH, &expired).into(),
        ))
        .await
        .expect("expired auth");
    closed(&mut rejected, 1008).await;
    drop((socket, rejected, listener));
    f.cleanup().await;
}

#[tokio::test]
async fn sqlite_real_tls_notifications_get_connect_delivery_and_revocation() {
    delivery(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_tls_notifications_authentication_and_wire_denials() {
    denials(Fixture::sqlite().await).await;
}
#[tokio::test]
async fn sqlite_real_tls_notifications_token_expiry() {
    expiry(Fixture::sqlite().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_tls_notifications_get_connect_delivery_and_revocation() {
    delivery(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_tls_notifications_authentication_and_wire_denials() {
    denials(Fixture::postgres().await).await;
}
#[cfg(feature = "postgres-integration")]
#[tokio::test]
async fn postgres_real_tls_notifications_token_expiry() {
    expiry(Fixture::postgres().await).await;
}
