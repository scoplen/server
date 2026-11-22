// SPDX-License-Identifier: AGPL-3.0-only
//! Exercise the real HTTPS client's sync-problem and retired-route response paths.

use super::tests::Scratch;
use super::*;
use axum::http::Response;
use scoplen_api::{ErrorCode, ProblemDetails};

#[tokio::test]
async fn sync_not_found_retains_cbor_while_retired_routes_require_only_status() {
    let scratch = Scratch::new();
    let listener = tokio::net::TcpListener::bind((Ipv4Addr::LOCALHOST, 0)).await.unwrap();
    let port = listener.local_addr().unwrap().port();
    prepare(&scratch.0, None, Some(port)).unwrap();
    let cert = fs::read(scratch.0.join("localhost.pem")).unwrap();
    let key = Zeroizing::new(fs::read(scratch.0.join("localhost-key.pem")).unwrap());
    let mut tls = rustls::ServerConfig::builder_with_provider(Arc::new(
        rustls::crypto::aws_lc_rs::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(
        rustls_pemfile::certs(&mut cert.as_slice())
            .collect::<std::result::Result<Vec<_>, _>>()
            .unwrap(),
        rustls_pemfile::private_key(&mut key.as_slice()).unwrap().unwrap(),
    )
    .unwrap();
    tls.alpn_protocols = vec![b"h2".to_vec()];
    let acceptor = tokio_rustls::TlsAcceptor::from(Arc::new(tls));
    let problem = ProblemDetails::new(
        ErrorCode::new("sync.object_not_found").unwrap(),
        404,
        "Object not found",
        "The vault is unavailable. No data changed.",
        "synthetic-request",
        false,
        false,
    )
    .unwrap();
    let body = problem.to_cbor().unwrap();
    let server_body = body.clone();
    let _server =
        Driver(tokio::spawn(async move {
            loop {
                let (tcp, _) = listener.accept().await.unwrap();
                let stream = acceptor.accept(tcp).await.unwrap();
                let body = server_body.clone();
                let service =
                    hyper::service::service_fn(move |request: Request<hyper::body::Incoming>| {
                        let query = request.uri().query();
                        let mut reply = Response::builder()
                            .status(if query == Some("wrong-status") { 200 } else { 404 });
                        let body = if request.uri().path().starts_with("/sync/") {
                            reply = reply.header(
                                "content-type",
                                if query == Some("wrong-type") {
                                    "application/cbor"
                                } else {
                                    "application/problem+cbor"
                                },
                            );
                            if query != Some("missing-privacy") {
                                reply = reply.header("cache-control", "no-store");
                            }
                            if query == Some("oversized") { vec![0; 65_537] } else { body.clone() }
                        } else {
                            Vec::new()
                        };
                        std::future::ready(Ok::<_, std::convert::Infallible>(
                            reply.body(Full::new(Bytes::from(body))).unwrap(),
                        ))
                    });
                let _ = hyper::server::conn::http2::Builder::new(TokioExecutor::new())
                    .serve_connection(TokioIo::new(stream), service)
                    .await;
            }
        }));
    let https = Https::new(&scratch.0, port, format!("https://localhost:{port}")).unwrap();
    let vault = uuid::Uuid::now_v7();
    for path in [
        format!("/sync/v1/vaults/{vault}/snapshot?after=0&limit=10"),
        format!("/sync/v1/vaults/{vault}/objects/{}/versions", uuid::Uuid::now_v7()),
    ] {
        let received = https.exchange("GET", &path, &[], None, 404).await.unwrap();
        assert_eq!(received.as_slice(), body);
        assert_eq!(ProblemDetails::from_cbor(&received).unwrap(), problem);
    }
    for query in ["wrong-type", "missing-privacy", "oversized", "wrong-status"] {
        let path = format!("/sync/v1/vaults/{vault}/snapshot?{query}");
        assert!(https.exchange("GET", &path, &[], None, 404).await.is_err());
    }
    for &(method, path) in RETIRED_ROUTES {
        assert_eq!(https.exchange(method, path, b"{}", None, 404).await.unwrap().len(), 0);
    }
    assert!(https.exchange("GET", "/pair?wrong-status", &[], None, 404).await.is_err());
}
