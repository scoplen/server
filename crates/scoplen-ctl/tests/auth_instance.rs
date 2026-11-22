// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    path::PathBuf,
    process::{Command, Output},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Router,
    body::Body,
    extract::Path,
    http::{HeaderMap, Response, StatusCode},
    routing::get,
};
use serde_json::json;

#[path = "common/https.rs"]
mod https;

async fn check(issuer: String, ca_file: Option<PathBuf>) -> Output {
    tokio::task::spawn_blocking(move || {
        let mut command = Command::new(env!("CARGO_BIN_EXE_splctl"));
        command.args(["auth", "check-instance", "--issuer", &issuer]);
        if let Some(ca) = ca_file {
            command.arg("--ca-certificate").arg(ca);
        }
        command.output().expect("check-instance CLI")
    })
    .await
    .expect("CLI task")
}

#[tokio::test]
async fn rejects_invalid_issuers_before_connecting() {
    for issuer in [
        "http://issuer.example.test",
        "https://private-marker@issuer.example.test",
        "https://issuer.example.test/?private-marker",
        "https://issuer.example.test/#private-marker",
        "/issuer",
    ] {
        let output = check(issuer.to_owned(), None).await;
        let reason = String::from_utf8_lossy(&output.stderr);
        assert!(!output.status.success());
        assert!(reason.contains("absolute HTTPS issuer"));
        assert!(!reason.contains("private-marker"));
    }
}

fn discovery_response(port: u16, scenario: &str) -> Response<Body> {
    let issuer = format!("https://127.0.0.1:{port}/{scenario}");
    let mut document = json!({
        "issuer": issuer,
        "authorization_endpoint": format!("{issuer}/authorize"),
        "token_endpoint": format!("{issuer}/token"),
        "userinfo_endpoint": format!("{issuer}/userinfo"),
        "jwks_uri": format!("{issuer}/jwks"),
        "response_types_supported": ["code"],
        "code_challenge_methods_supported": ["S256"],
        "scopes_supported": ["openid"],
        "subject_types_supported": ["public"],
        "id_token_signing_alg_values_supported": ["ES256"]
    });
    let json_response =
        Response::builder().header("content-type", "application/json; charset=utf-8");
    match scenario {
        "tenant" => {}
        "mismatch" => document["issuer"] = json!("https://other.example.test"),
        "missing" => document["scopes_supported"] = json!(["email"]),
        "keyset" => document["jwks_uri"] = json!("http://example.test/keys"),
        "agent" => document["grant_types_supported"] = json!(["refresh_token"]),
        "redirect" => {
            return Response::builder()
                .status(StatusCode::FOUND)
                .header("location", "/tenant/.well-known/openid-configuration")
                .body(Body::empty())
                .expect("redirect");
        }
        "invalid" => {
            return json_response
                .body(Body::from("private-response-marker"))
                .expect("JSON response");
        }
        "large" => {
            return json_response.body(Body::from(vec![b' '; 65_537])).expect("large response");
        }
        _ => panic!("unexpected fixture route"),
    }
    json_response.body(Body::from(document.to_string())).expect("discovery response")
}

#[tokio::test]
async fn checks_only_the_configured_instances_discovery_and_requires_trusted_login_metadata() {
    let dir = std::env::temp_dir().join(format!("spl-issuer-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).expect("create fixture");
    let count = Arc::new(AtomicUsize::new(0));
    let calls = Arc::clone(&count);
    let unexpected = Arc::clone(&count);
    let (port, task) = https::start(&dir, false, move |port| {
        Router::new()
            .route(
                "/{scenario}/.well-known/openid-configuration",
                get(move |Path(scenario): Path<String>, headers: HeaderMap| {
                    calls.fetch_add(1, Ordering::SeqCst);
                    async move {
                        assert!(
                            !headers.contains_key("authorization")
                                && !headers.contains_key("cookie")
                        );
                        discovery_response(port, &scenario)
                    }
                }),
            )
            .fallback(move || {
                unexpected.fetch_add(1, Ordering::SeqCst);
                async { axum::http::StatusCode::NOT_FOUND }
            })
    })
    .await;
    let issuer = format!("https://127.0.0.1:{port}");
    let ca = dir.join("ca.pem");
    let untrusted = check(format!("{issuer}/tenant"), None).await;
    assert!(!untrusted.status.success());
    assert_eq!(count.load(Ordering::SeqCst), 0);
    for (index, (scenario, expected)) in [
        ("tenant", "PASS"),
        ("mismatch", "issuer mismatch"),
        ("missing", "openid scope"),
        ("keyset", "advertised endpoint"),
        ("agent", "authorization code grant"),
        ("redirect", "HTTP 200"),
        ("invalid", "invalid discovery"),
        ("large", "64 KiB"),
    ]
    .into_iter()
    .enumerate()
    {
        let out = check(format!("{issuer}/{scenario}"), Some(ca.clone())).await;
        assert_eq!(out.status.success(), scenario == "tenant");
        let report = format!(
            "{}{}",
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        );
        assert!(
            report.contains(expected)
                && !report.contains("127.0.0.1")
                && !report.contains("private-response-marker"),
            "unexpected diagnostic for {scenario}"
        );
        assert_eq!(count.load(Ordering::SeqCst), index + 1);
    }
    task.abort();
    fs::remove_file(ca).expect("remove test CA");
    fs::remove_dir(dir).expect("there should be no new deployment files");
}
