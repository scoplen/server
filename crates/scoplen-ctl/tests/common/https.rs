// SPDX-License-Identifier: AGPL-3.0-only

use axum::Router;
use hyper_util::{
    rt::{TokioExecutor, TokioIo},
    server::conn::auto::Builder,
    service::TowerToHyperService,
};
use rcgen::{
    BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, KeyPair,
    KeyUsagePurpose,
};
use std::{fs, path::Path, sync::Arc};
use tokio::{net::TcpListener, task::JoinSet};
use tokio_rustls::TlsAcceptor;

pub async fn start(
    directory: &Path,
    wrong_hostname: bool,
    build: impl FnOnce(u16) -> Router,
) -> (u16, tokio::task::JoinHandle<()>) {
    let root_key = KeyPair::generate().expect("fixture CA key");
    let mut root_params = CertificateParams::new(Vec::<String>::new()).expect("CA parameters");
    root_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    root_params.distinguished_name.push(DnType::CommonName, "Doctor test root CA");
    root_params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
    let root = root_params.self_signed(&root_key).expect("fixture CA");
    let key = KeyPair::generate().expect("fixture server key");
    let names = if wrong_hostname {
        vec!["wrong.example.test".into()]
    } else {
        vec!["127.0.0.1".into(), "localhost".into()]
    };
    let mut params = CertificateParams::new(names).expect("fixture certificate parameters");
    params.distinguished_name.push(DnType::CommonName, "Doctor test HTTPS endpoint");
    params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    let certificate = params.signed_by(&key, &root, &root_key).expect("fixture certificate");
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_safe_default_protocol_versions()
    .expect("TLS versions")
    .with_no_client_auth()
    .with_single_cert(
        vec![certificate.der().clone(), root.der().clone()],
        rustls::pki_types::PrivatePkcs8KeyDer::from(key.serialize_der()).into(),
    )
    .expect("fixture TLS");
    tls.alpn_protocols = vec![b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(Arc::new(tls));
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("owned TLS listener");
    let port = listener.local_addr().expect("fixture address").port();
    fs::write(directory.join("ca.pem"), root.pem()).expect("fixture CA file");
    let router = build(port);
    let server = tokio::spawn(async move {
        let mut connections = JoinSet::new();
        loop {
            tokio::select! {
                incoming = listener.accept() => {
                    let Ok((tcp, _)) = incoming else { break };
                    let acceptor = acceptor.clone();
                    let router = router.clone();
                    connections.spawn(async move {
                        if let Ok(tls) = acceptor.accept(tcp).await {
                            let _ = Builder::new(TokioExecutor::new()).serve_connection(TokioIo::new(tls), TowerToHyperService::new(router)).await;
                        }
                    });
                }
                _ = connections.join_next(), if !connections.is_empty() => {}
            }
        }
    });
    (port, server)
}
