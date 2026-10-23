// SPDX-License-Identifier: AGPL-3.0-only
use super::*;
use scoplen_crypto::{DpopProof, DpopTarget, DpopToken};
use scoplen_store::RelationalStore;
use serde_json::json;
use tokio::{io::AsyncWriteExt, net::TcpListener};

fn directory() -> std::path::PathBuf {
    std::env::temp_dir().join(format!("scoplen-console-{}", uuid::Uuid::new_v4()))
}

async fn fixture(directory: &Path) {
    tokio::fs::create_dir_all(directory.join("assets")).await.expect("owned assets directory");
    let mut entries = Vec::new();
    for (path, content) in [
        ("index.html", "<!doctype html><title>Console</title>"),
        ("assets/console-a.js", "export const consoleName = 'Scoplen';"),
    ] {
        tokio::fs::write(directory.join(path), content).await.expect("asset fixture");
        entries.push(json!({ "path": path, "bytes": content.len(), "sha256": format!("{:x}", Sha256::digest(content)) }));
    }
    tokio::fs::write(
        directory.join("manifest.json"),
        serde_json::to_vec(&json!({ "version": 1, "assets": entries })).expect("manifest"),
    )
    .await
    .expect("manifest fixture");
}

async fn get(router: Router, path: &str) -> String {
    let listener = TcpListener::bind("127.0.0.1:0").await.expect("owned listener");
    let address = listener.local_addr().expect("listener address");
    let server = tokio::spawn(async move {
        axum::serve(listener, router.into_make_service_with_connect_info::<std::net::SocketAddr>())
            .await
            .expect("HTTP server");
    });
    let mut stream = tokio::net::TcpStream::connect(address).await.expect("connect");
    stream
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await
        .expect("send public HTTP request");
    let mut bytes = Vec::new();
    stream.read_to_end(&mut bytes).await.expect("read response");
    server.abort();
    let _ = server.await;
    String::from_utf8(bytes).expect("text fixture")
}

#[tokio::test]
async fn real_http_serves_only_manifest_paths_with_strict_headers() {
    let root = directory();
    fixture(&root).await;
    let router = router(&root, true).await;
    for path in ["/", "/setup"] {
        let response = get(router.clone(), path).await;
        assert!(response.starts_with("HTTP/1.1 200 OK"));
        for header in [
            "content-type: text/html; charset=utf-8",
            "cache-control: no-store",
            "referrer-policy: no-referrer",
            "x-content-type-options: nosniff",
            "frame-ancestors 'none'",
            "require-trusted-types-for 'script'",
            "trusted-types 'none'",
        ] {
            assert!(response.contains(header), "{header}");
        }
        assert!(response.ends_with("<!doctype html><title>Console</title>"));
    }
    let js = get(router.clone(), "/assets/console-a.js").await;
    assert!(js.contains("content-type: text/javascript; charset=utf-8"));
    for path in [
        "/manifest.json",
        "/assets/not-listed.js",
        "/login",
        "/assets/..%2Fmanifest.json",
        "/assets/%2E%2E%2Findex.html",
        "/assets/console-a.js/extra",
    ] {
        assert!(get(router.clone(), path).await.starts_with("HTTP/1.1 404 Not Found"), "{path}");
    }
    tokio::fs::write(root.join("index.html"), "changed after startup")
        .await
        .expect("mutate fixture");
    assert!(get(router, "/").await.ends_with("<!doctype html><title>Console</title>"));
    assert_eq!(load(&root).await.err(), Some("asset integrity mismatch"));
    tokio::fs::remove_dir_all(root).await.expect("remove owned assets");
}

#[tokio::test]
async fn missing_console_keeps_real_api_health_and_readiness_independent() {
    let root = directory();
    let mut config = crate::Config::default();
    config.server.data_dir = root.clone();
    let prepared =
        crate::prepare_roles(&config, &[crate::Role::Api]).await.expect("prepare real API");
    let store = prepared.store.expect("SQLite store");
    let router = crate::runtime::api_router(
        crate::runtime::ListenerDatabase::Sqlite(Arc::new(store.clone())),
        Arc::new(prepared.object_storage.expect("object storage")),
        Arc::new(prepared.key_management.expect("KMS")),
        config.public_origin().expect("origin"),
        true,
    )
    .merge(router(&root.join("missing-assets"), true).await);
    for path in ["/", "/setup"] {
        let response = get(router.clone(), path).await;
        assert!(response.starts_with("HTTP/1.1 503 Service Unavailable"));
        assert!(response.contains("cache-control: no-store"));
        assert!(response.contains("pnpm --dir web/console build"));
        assert!(!response.contains(&root.to_string_lossy().into_owned()));
    }
    for path in ["/healthz", "/readyz", "/metrics"] {
        assert!(get(router.clone(), path).await.starts_with("HTTP/1.1 200 OK"));
    }
    assert!(
        get(router, "/api/v1/auth/operator/login/options")
            .await
            .starts_with("HTTP/1.1 405 Method Not Allowed")
    );
    store.pool().close().await;
    drop(store);
    tokio::fs::remove_dir_all(root).await.expect("remove owned API directory");
}

#[tokio::test]
async fn malformed_or_unbounded_manifests_fail_closed_and_edge_has_no_console() {
    let root = directory();
    fixture(&root).await;
    let manifest = tokio::fs::read(root.join("manifest.json")).await.expect("manifest");
    let base: serde_json::Value = serde_json::from_slice(&manifest).expect("fixture");
    let mut mutations = Vec::new();
    for path in [
        "../index.html",
        "assets/../index.html",
        "/index.html",
        "assets/secret.txt",
        "assets/.hidden.js",
        "assets/a%2fb.js",
    ] {
        let mut value = base.clone();
        value["assets"][0]["path"] = path.into();
        mutations.push(value);
    }
    for field in ["bytes", "sha256"] {
        let mut value = base.clone();
        value["assets"][0][field] =
            if field == "bytes" { json!(MAX_ASSET_BYTES + 1) } else { json!("0".repeat(64)) };
        mutations.push(value);
    }
    let mut duplicate = base.clone();
    duplicate["assets"].as_array_mut().expect("entries").push(base["assets"][0].clone());
    mutations.push(duplicate);
    let mut version = base.clone();
    version["version"] = 2.into();
    mutations.push(version);
    mutations.push(json!({"version": 1, "assets": [base["assets"][1].clone()]}));
    for manifest in mutations {
        tokio::fs::write(
            root.join("manifest.json"),
            serde_json::to_vec(&manifest).expect("mutation"),
        )
        .await
        .expect("write mutation");
        assert!(load(&root).await.is_err());
        assert!(
            get(router(&root, true).await, "/setup")
                .await
                .starts_with("HTTP/1.1 503 Service Unavailable")
        );
    }
    tokio::fs::write(root.join("manifest.json"), vec![b' '; MAX_MANIFEST_BYTES + 1])
        .await
        .expect("large manifest");
    assert_eq!(load(&root).await.err(), Some("asset exceeds size limit"));
    assert!(get(router(&root, false).await, "/").await.starts_with("HTTP/1.1 404 Not Found"));
    tokio::fs::remove_dir_all(root).await.expect("remove owned assets");
}

#[test]
fn actual_console_webcrypto_proofs_interoperate_with_shared_server_verifier() {
    #[derive(Deserialize)]
    struct Fixture {
        origin: String,
        path: String,
        access_token: String,
        now: u64,
        authentication: String,
        protected_request: String,
    }
    let fixture: Fixture =
        serde_json::from_str(include_str!("dpop-webcrypto.json")).expect("WebCrypto fixture");
    let auth =
        DpopProof::parse(&fixture.authentication).expect("actual console authentication proof");
    let auth_target =
        DpopTarget::new("POST", &fixture.origin, "/api/v1/auth/operator/login/options")
            .expect("target");
    let key = auth
        .verify_presented_key(&auth_target, DpopToken::Refresh, fixture.now, None)
        .expect("shared verifier accepts WebCrypto signature")
        .jkt;
    let protected =
        DpopProof::parse(&fixture.protected_request).expect("actual console protected proof");
    let target = DpopTarget::new("POST", &fixture.origin, &fixture.path).expect("target");
    protected
        .verify(&target, DpopToken::Protected(&fixture.access_token), &key, fixture.now, None)
        .expect("original access-token hash and browser key match");
    assert!(
        protected
            .verify(
                &target,
                DpopToken::Protected("different-access-token"),
                &key,
                fixture.now,
                None
            )
            .is_err()
    );
    assert!(
        protected
            .verify(
                &target,
                DpopToken::Protected(&fixture.access_token),
                "wrong-thumbprint",
                fixture.now,
                None
            )
            .is_err()
    );
    assert!(
        protected
            .verify(
                &auth_target,
                DpopToken::Protected(&fixture.access_token),
                &key,
                fixture.now,
                None
            )
            .is_err()
    );
}
