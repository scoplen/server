// SPDX-License-Identifier: AGPL-3.0-only
//! Certificate-verified HTTPS transport for the public team API fixture.

use super::*;
use axum::{Extension, body::Body, extract::ConnectInfo, http::Request};
use hyper_util::rt::TokioIo;
use rustls::{
    ClientConfig, RootCertStore, ServerConfig,
    pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer, ServerName},
};
use tokio_rustls::{TlsAcceptor, TlsConnector};

mod personal;
pub(super) use personal::personal_sync_after_revocation;

pub(super) struct TlsFixture {
    address: SocketAddr,
    roots: RootCertStore,
    task: JoinHandle<()>,
}

impl Drop for TlsFixture {
    fn drop(&mut self) {
        self.task.abort();
    }
}

impl TlsFixture {
    pub(super) async fn start(f: &Fixture) -> Self {
        Self::start_with_enterprise_identity(f, crate::EnterpriseIdentitySettings::default()).await
    }

    pub(super) async fn start_with_enterprise_identity(
        f: &Fixture,
        settings: crate::EnterpriseIdentitySettings,
    ) -> Self {
        let app = Fixture::app(
            &f.backend,
            &f.directory,
            test_kms(),
            f.notifications.clone(),
            scoplen_sync::http::ReadBodyLimits::default(),
            settings,
        );
        let rcgen::CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["example.com".into()]).unwrap();
        let key = PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(key_pair.serialize_der()));
        let mut config = ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(vec![cert.der().clone()], key)
        .unwrap();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let acceptor = TlsAcceptor::from(Arc::new(config));
        let mut roots = RootCertStore::empty();
        roots.add(cert.der().clone()).unwrap();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut connections = tokio::task::JoinSet::new();
            loop {
                tokio::select! {
                    connection=listener.accept()=>{
                        let (tcp,peer)=connection.unwrap();
                        let app=app.clone().layer(Extension(ConnectInfo(peer)));
                        let acceptor=acceptor.clone();
                        connections.spawn(async move {
                            let tls=acceptor.accept(tcp).await.unwrap();
                            let _=crate::runtime::serve_tls_io(tls,app,false).await;
                        });
                    }
                    Some(result)=connections.join_next()=>{result.unwrap();}
                }
            }
        });
        Self { address, roots, task }
    }

    pub(super) async fn get(&self, actor: &Actor, path: &str) -> Reply {
        self.request(actor, "GET", path, &[]).await
    }

    pub(super) async fn request(
        &self,
        actor: &Actor,
        method: &str,
        path: &str,
        body: &[u8],
    ) -> Reply {
        let mut request =
            Self::signed(&actor.registration.device, &actor.token.access_token, method, path)
                .header("Origin", ORIGIN);
        if path.starts_with("/sync/") {
            request = request.header("Content-Type", "application/cbor");
        }
        let request = request.body(Body::from(body.to_vec())).unwrap();
        self.send(request).await
    }

    pub(super) fn signed(
        key: &P256SigningKey,
        token: &str,
        method: &str,
        path: &str,
    ) -> axum::http::request::Builder {
        let proof = DpopProof::sign(
            key,
            &key.public_key_sec1(),
            &DpopTarget::new(method, ORIGIN, path.split('?').next().unwrap()).unwrap(),
            DpopToken::Protected(token),
            u64::try_from(time::OffsetDateTime::now_utc().unix_timestamp()).unwrap(),
            None,
        )
        .unwrap();
        Request::builder()
            .method(method)
            .uri(path)
            .header("Host", "example.com")
            .header("Authorization", format!("DPoP {token}"))
            .header("DPoP", proof.as_str())
    }

    pub(super) async fn send(&self, request: Request<Body>) -> Reply {
        let mut config = ClientConfig::builder_with_provider(Arc::new(
            rustls::crypto::aws_lc_rs::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(self.roots.clone())
        .with_no_client_auth();
        config.alpn_protocols = vec![b"http/1.1".to_vec()];
        let tls = TlsConnector::from(Arc::new(config))
            .connect(
                ServerName::try_from("example.com").unwrap(),
                TcpStream::connect(self.address).await.unwrap(),
            )
            .await
            .unwrap();
        let (mut sender, connection) =
            hyper::client::conn::http1::handshake(TokioIo::new(tls)).await.unwrap();
        let task = tokio::spawn(async move {
            let _ = connection.await;
        });
        let response = sender.send_request(request).await.unwrap();
        let status = response.status().as_u16();
        let mut headers = String::new();
        for (name, value) in response.headers() {
            write!(headers, "{name}: {}\r\n", value.to_str().unwrap()).unwrap();
        }
        let body = response.into_body().collect().await.unwrap().to_bytes().to_vec();
        drop(sender);
        task.abort();
        Reply { status, headers, body }
    }
}
