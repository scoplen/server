// SPDX-License-Identifier: AGPL-3.0-only
use std::sync::{
    Arc,
    atomic::{AtomicBool, AtomicUsize, Ordering},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};

pub struct LostCommitProxy {
    pub database_url: String,
    pub armed: Arc<AtomicBool>,
    pub dropped: Arc<AtomicUsize>,
    task: tokio::task::JoinHandle<()>,
}

impl Drop for LostCommitProxy {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl LostCommitProxy {
    pub async fn start(database_url: &str) -> Self {
        let mut url = url::Url::parse(database_url).expect("TCP PostgreSQL URL");
        let upstream = format!("{}:{}", url.host_str().expect("host"), url.port().unwrap_or(5432));
        let listener = TcpListener::bind("127.0.0.1:0").await.expect("proxy listener");
        url.set_host(Some("127.0.0.1")).expect("proxy host");
        url.set_port(Some(listener.local_addr().expect("address").port())).expect("proxy port");
        url.query_pairs_mut().append_pair("sslmode", "disable");
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
