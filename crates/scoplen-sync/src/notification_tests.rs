// SPDX-License-Identifier: AGPL-3.0-only

use super::*;
use std::{
    pin::Pin,
    task::{Context, Poll},
};
use tokio::io::{AsyncRead, AsyncWrite, DuplexStream, ReadBuf};
use tokio_tungstenite::{
    WebSocketStream,
    tungstenite::protocol::frame::{
        Frame,
        coding::{Data, OpCode},
    },
};

fn credentials() -> Vec<u8> {
    api::SyncNotificationAuth {
        access_token: "bm90aWZ5.dGVzdA.dG9rZW4".into(),
        dpop_proof: "ZA.ZQ.Zg".into(),
    }
    .to_cbor()
    .expect("credentials")
}

fn fragment(body: Vec<u8>, first: bool, last: bool) -> ClientMessage {
    ClientMessage::Frame(Frame::message(
        body,
        OpCode::Data(if first { Data::Binary } else { Data::Continue }),
        last,
    ))
}

async fn message<S: AsyncRead + AsyncWrite + Unpin>(
    socket: &mut WebSocketStream<S>,
) -> ClientMessage {
    tokio::time::timeout(Duration::from_secs(12), socket.next())
        .await
        .expect("bounded response")
        .expect("message")
        .expect("frame")
}

async fn context<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut WebSocketStream<S>) {
    let ClientMessage::Binary(body) = message(socket).await else { panic!("context") };
    api::SyncNotificationContext::from_cbor(&body).expect("context codec");
}

async fn ready<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut WebSocketStream<S>) {
    let ClientMessage::Binary(body) = message(socket).await else { panic!("ready") };
    api::SyncNotificationReady::from_cbor(&body).expect("ready codec");
}

async fn closed<S: AsyncRead + AsyncWrite + Unpin>(socket: &mut WebSocketStream<S>, code: u16) {
    let ClientMessage::Close(Some(frame)) = message(socket).await else {
        panic!("close without ready")
    };
    assert_eq!(u16::from(frame.code), code);
}

#[tokio::test]
async fn fragmented_authentication_uses_the_complete_message_limit() {
    let (store, _, device) = test_store().await;
    let app = router(store, TestAuthenticator::new(device, true));
    let (address, server) = notification_server(app).await;
    let (mut socket, _) =
        connect_async(format!("ws://{address}/sync/v1/notify")).await.expect("connect");
    context(&mut socket).await;
    let body = credentials();
    socket.send(fragment(body[..20].to_vec(), true, false)).await.expect("initial fragment");
    socket.send(ClientMessage::Ping(vec![1].into())).await.expect("interleaved control");
    assert_eq!(message(&mut socket).await, ClientMessage::Pong(vec![1].into()));
    assert!(tokio::time::timeout(Duration::from_millis(20), socket.next()).await.is_err());
    socket.send(fragment(body[20..].to_vec(), false, true)).await.expect("final fragment");
    ready(&mut socket).await;
    socket.close(None).await.expect("close");
    for (length, code) in [(16_384, 1008), (16_385, 1009)] {
        let (mut socket, _) =
            connect_async(format!("ws://{address}/sync/v1/notify")).await.expect("connect");
        context(&mut socket).await;
        socket.send(fragment(vec![0; 8_192], true, false)).await.expect("initial fragment");
        socket.send(fragment(vec![0; length - 8_192], false, true)).await.expect("final fragment");
        closed(&mut socket, code).await;
    }
    server.abort();
}

#[tokio::test]
async fn malformed_frames_keep_protocol_and_encoding_close_codes() {
    let (store, _, device) = test_store().await;
    let app = router(store, TestAuthenticator::new(device, true));
    let (address, server) = notification_server(app).await;
    for (opcode, body, code) in [(Data::Continue, vec![0], 1002), (Data::Text, vec![0xff], 1007)] {
        let (mut socket, _) =
            connect_async(format!("ws://{address}/sync/v1/notify")).await.expect("connect");
        context(&mut socket).await;
        socket
            .send(ClientMessage::Frame(Frame::message(body, OpCode::Data(opcode), true)))
            .await
            .expect("invalid protocol frame");
        closed(&mut socket, code).await;
    }
    server.abort();
}

#[tokio::test]
async fn incomplete_authentication_and_control_frames_do_not_extend_the_deadline() {
    let (store, _, device) = test_store().await;
    let (address, server) =
        notification_server(router(store, TestAuthenticator::new(device, true))).await;
    let (mut socket, _) =
        connect_async(format!("ws://{address}/sync/v1/notify")).await.expect("connect");
    context(&mut socket).await;
    let started = tokio::time::Instant::now();
    socket
        .send(fragment(credentials()[..20].to_vec(), true, false))
        .await
        .expect("initial fragment");
    tokio::time::sleep(Duration::from_secs(2)).await;
    socket.send(ClientMessage::Ping(vec![1].into())).await.expect("control frame");
    assert_eq!(message(&mut socket).await, ClientMessage::Pong(vec![1].into()));
    closed(&mut socket, 1008).await;
    assert!(started.elapsed() < Duration::from_secs(11));
    server.abort();
}

#[tokio::test]
async fn authentication_deadline_includes_credential_verification() {
    let (store, _, device) = test_store().await;
    let mut authenticator = TestAuthenticator::new(device, true);
    authenticator.notification_auth_delay = Duration::from_secs(11);
    let (address, server) = notification_server(router(store, authenticator)).await;
    let (mut socket, _) =
        connect_async(format!("ws://{address}/sync/v1/notify")).await.expect("connect");
    context(&mut socket).await;
    let started = tokio::time::Instant::now();
    tokio::time::sleep(Duration::from_secs(2)).await;
    socket.send(ClientMessage::Binary(credentials().into())).await.expect("credentials");
    closed(&mut socket, 1008).await;
    assert!(started.elapsed() < Duration::from_secs(11));
    server.abort();
}

#[tokio::test]
async fn stalled_current_state_check_closes_without_waiting_for_token_expiry() {
    let (store, _, device) = test_store().await;
    let authenticator = TestAuthenticator::new(device, true);
    let stalled = authenticator.notification_check_stalled.clone();
    let hub = NotificationHub::default();
    let (address, server) =
        notification_server(router_with_notifications(store, authenticator, hub.clone())).await;
    let (mut socket, _) =
        connect_async(format!("ws://{address}/sync/v1/notify")).await.expect("connect");
    context(&mut socket).await;
    socket.send(ClientMessage::Binary(credentials().into())).await.expect("credentials");
    ready(&mut socket).await;
    let started = tokio::time::Instant::now();
    stalled.store(true, Ordering::SeqCst);
    closed(&mut socket, 1011).await;
    assert!(started.elapsed() < Duration::from_secs(7));
    assert_eq!(hub.receiver_count(TestAuthenticator::identity(device)), 0);
    server.abort();
}

struct BoundedTransport {
    stream: DuplexStream,
    stalled: Arc<AtomicBool>,
}

impl AsyncRead for BoundedTransport {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        body: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, body)
    }
}

impl AsyncWrite for BoundedTransport {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        body: &[u8],
    ) -> Poll<std::io::Result<usize>> {
        let result = Pin::new(&mut self.stream).poll_write(cx, body);
        if result.is_pending() {
            self.stalled.store(true, Ordering::SeqCst);
        }
        result
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

struct Once(Option<BoundedTransport>);

impl axum::serve::Listener for Once {
    type Io = BoundedTransport;
    type Addr = ();
    async fn accept(&mut self) -> (Self::Io, ()) {
        match self.0.take() {
            Some(stream) => (stream, ()),
            None => std::future::pending().await,
        }
    }
    fn local_addr(&self) -> std::io::Result<()> {
        Ok(())
    }
}

#[tokio::test]
async fn stalled_event_transport_unsubscribes_without_waiting_for_token_expiry() {
    let (store, _, device) = test_store().await;
    let hub = NotificationHub::default();
    let app = router_with_notifications(store, TestAuthenticator::new(device, true), hub.clone());
    let (client, transport) = tokio::io::duplex(64);
    let stalled = Arc::new(AtomicBool::new(false));
    let listener = Once(Some(BoundedTransport { stream: transport, stalled: stalled.clone() }));
    let server = tokio::spawn(async move {
        axum::serve(listener, app).await.expect("serve");
    });
    let (mut socket, _) = tokio_tungstenite::client_async("ws://localhost/sync/v1/notify", client)
        .await
        .expect("connect");
    context(&mut socket).await;
    socket.send(ClientMessage::Binary(credentials().into())).await.expect("credentials");
    ready(&mut socket).await;
    stalled.store(false, Ordering::SeqCst);
    let identity = TestAuthenticator::identity(device);
    let event = api::SyncNotification::VaultAdvanced { vault: Uuid::now_v7(), seq: 1 };
    for _ in 0..20 {
        assert_eq!(hub.publish(identity, &event).expect("event"), 1);
        tokio::time::sleep(Duration::from_millis(10)).await;
        if stalled.load(Ordering::SeqCst) {
            break;
        }
    }
    assert!(stalled.load(Ordering::SeqCst), "non-reading client must stall the real transport");
    tokio::time::timeout(Duration::from_secs(3), async {
        while hub.receiver_count(identity) != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .expect("stalled connection unsubscribed");
    server.abort();
}
