// SPDX-License-Identifier: AGPL-3.0-only
//! Bounded D-75 notification handshake and authenticated connection lifecycle.

use std::time::{Duration, SystemTime, UNIX_EPOCH};

use axum::{
    extract::{
        State, WebSocketUpgrade,
        ws::{CloseFrame, Message, WebSocket},
    },
    http::{Method, Uri},
    response::IntoResponse,
};
use scoplen_api::sync as api;
use tokio::{
    sync::broadcast,
    time::{Instant, MissedTickBehavior, timeout_at},
};

use super::{AuthenticatedNotification, SyncAuthenticator, SyncHttpState};

const AUTH_TIMEOUT: Duration = Duration::from_secs(api::SYNC_NOTIFICATION_AUTH_DEADLINE_SECS);
const CURRENT_STATE_INTERVAL: Duration = Duration::from_secs(1);
const CURRENT_STATE_TIMEOUT: Duration = Duration::from_secs(5);
const SEND_TIMEOUT: Duration = Duration::from_secs(1);

pub(super) async fn notify<A: SyncAuthenticator>(
    ws: WebSocketUpgrade,
    State(state): State<SyncHttpState<A>>,
    method: Method,
    uri: Uri,
) -> impl IntoResponse {
    let deadline = Instant::now() + AUTH_TIMEOUT;
    ws.max_message_size(api::MAX_SYNC_NOTIFICATION_BODY_BYTES)
        .max_frame_size(api::MAX_SYNC_NOTIFICATION_BODY_BYTES)
        .on_upgrade(move |socket| session(socket, state, method, uri, deadline))
}

async fn session<A: SyncAuthenticator>(
    mut socket: WebSocket,
    state: SyncHttpState<A>,
    method: Method,
    uri: Uri,
    deadline: Instant,
) {
    let result = timeout_at(deadline, authenticate(&mut socket, &state, &method, &uri)).await;
    if Instant::now() >= deadline {
        close(&mut socket, Failure::Policy).await;
        return;
    }
    let authenticated = match result {
        Ok(Ok(value)) => value,
        Ok(Err(failure)) => {
            close(&mut socket, failure).await;
            return;
        }
        Err(_) => {
            close(&mut socket, Failure::Policy).await;
            return;
        }
    };
    let Ok(now) = SystemTime::now().duration_since(UNIX_EPOCH) else {
        close(&mut socket, Failure::Internal).await;
        return;
    };
    let Some(remaining) = Duration::from_secs(authenticated.expires_at).checked_sub(now) else {
        close(&mut socket, Failure::Policy).await;
        return;
    };
    let Some(expires) = Instant::now().checked_add(remaining) else {
        close(&mut socket, Failure::Internal).await;
        return;
    };
    let mut events = state.notifications.subscribe(authenticated.identity);
    let ready = api::SyncNotificationReady.to_cbor().expect("static notification acknowledgement");
    if !matches!(
        timeout_at(deadline.min(expires), socket.send(Message::Binary(ready.into()))).await,
        Ok(Ok(()))
    ) {
        close(&mut socket, Failure::Policy).await;
        return;
    }
    let mut guard =
        tokio::time::interval_at(Instant::now() + CURRENT_STATE_INTERVAL, CURRENT_STATE_INTERVAL);
    guard.set_missed_tick_behavior(MissedTickBehavior::Skip);
    loop {
        tokio::select! {
            biased;
            () = tokio::time::sleep_until(expires) => {
                close(&mut socket, Failure::Policy).await;
                return;
            }
            _ = guard.tick() => {
                if let Err(failure) = current(&state, authenticated, expires).await {
                    close(&mut socket, failure).await;
                    return;
                }
            }
            incoming = socket.recv() => match application(incoming) {
                Ok(None) => {}
                Ok(Some(_)) => { close(&mut socket, Failure::Policy).await; return; }
                Err(failure) => { close(&mut socket, failure).await; return; }
            },
            event = events.recv() => match event {
                Ok(payload) => {
                    if let Err(failure) = current(&state, authenticated, expires).await {
                        close(&mut socket, failure).await;
                        return;
                    }
                    if !matches!(timeout_at(expires.min(Instant::now() + SEND_TIMEOUT), socket.send(Message::Binary(payload.into()))).await, Ok(Ok(()))) {
                        return;
                    }
                }
                Err(broadcast::error::RecvError::Lagged(_)) => {
                    close(&mut socket, Failure::Internal).await;
                    return;
                }
                Err(broadcast::error::RecvError::Closed) => return,
            },
        }
    }
}

async fn authenticate<A: SyncAuthenticator>(
    socket: &mut WebSocket,
    state: &SyncHttpState<A>,
    method: &Method,
    uri: &Uri,
) -> Result<AuthenticatedNotification, Failure> {
    let htm = match *method {
        Method::GET => api::SyncNotificationMethod::Get,
        Method::CONNECT => api::SyncNotificationMethod::Connect,
        _ => return Err(Failure::Policy),
    };
    let context =
        api::SyncNotificationContext { htm }.to_cbor().expect("static notification context");
    socket.send(Message::Binary(context.into())).await.map_err(|_| Failure::Disconnected)?;
    let credentials = loop {
        if let Some(bytes) = application(socket.recv().await)? {
            break api::SyncNotificationAuth::from_cbor(&bytes).map_err(|_| Failure::Policy)?;
        }
    };
    let authenticated = state
        .authenticator
        .authenticate_notification(method, uri, &credentials)
        .await
        .map_err(|error| Failure::auth(&error))?;
    state
        .authenticator
        .authorize_notifications(authenticated.identity)
        .await
        .map_err(|error| Failure::auth(&error))?;
    Ok(authenticated)
}

async fn current<A: SyncAuthenticator>(
    state: &SyncHttpState<A>,
    authenticated: AuthenticatedNotification,
    expires: Instant,
) -> Result<(), Failure> {
    let deadline = expires.min(Instant::now() + CURRENT_STATE_TIMEOUT);
    let result =
        timeout_at(deadline, state.authenticator.authorize_notifications(authenticated.identity))
            .await;
    if Instant::now() >= expires {
        return Err(Failure::Policy);
    }
    if Instant::now() >= deadline {
        return Err(Failure::Internal);
    }
    result.map_err(|_| Failure::Internal)?.map_err(|error| Failure::auth(&error))
}

enum Failure {
    TooLarge,
    Text,
    Policy,
    Internal,
    Protocol,
    Encoding,
    Disconnected,
}

impl Failure {
    fn auth(error: &super::AuthFailure) -> Self {
        if error.status.is_server_error() { Self::Internal } else { Self::Policy }
    }
}

fn application(incoming: Option<Result<Message, axum::Error>>) -> Result<Option<Vec<u8>>, Failure> {
    match incoming {
        Some(Ok(message)) => {
            let length = match &message {
                Message::Binary(value) => value.len(),
                Message::Text(value) => value.len(),
                _ => 0,
            };
            if length > api::MAX_SYNC_NOTIFICATION_BODY_BYTES {
                return Err(Failure::TooLarge);
            }
            match message {
                Message::Binary(value) => Ok(Some(value.to_vec())),
                Message::Text(_) => Err(Failure::Text),
                Message::Ping(_) | Message::Pong(_) => Ok(None),
                Message::Close(_) => Err(Failure::Disconnected),
            }
        }
        Some(Err(error)) => {
            let error = error.into_inner();
            match error.downcast_ref::<tungstenite::Error>() {
                Some(tungstenite::Error::Capacity(_)) => Err(Failure::TooLarge),
                Some(tungstenite::Error::Protocol(_)) => Err(Failure::Protocol),
                Some(tungstenite::Error::Utf8(_)) => Err(Failure::Encoding),
                _ => Err(Failure::Disconnected),
            }
        }
        None => Err(Failure::Disconnected),
    }
}

async fn close(socket: &mut WebSocket, failure: Failure) {
    let (code, reason) = match failure {
        Failure::TooLarge => (1009, "sync.notification_too_large"),
        Failure::Text => (1003, "sync.notification_binary_required"),
        Failure::Policy => (1008, "auth.authentication_required"),
        Failure::Internal => (1011, "sync.notification_unavailable"),
        Failure::Protocol => (1002, "sync.notification_protocol_error"),
        Failure::Encoding => (1007, "sync.notification_invalid_data"),
        Failure::Disconnected => return,
    };
    let _ = tokio::time::timeout(
        Duration::from_secs(1),
        socket.send(Message::Close(Some(CloseFrame { code, reason: reason.into() }))),
    )
    .await;
}
