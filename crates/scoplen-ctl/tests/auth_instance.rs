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

#[tokio::test]
async fn both_commands_reject_invalid_organization_issuers_before_io() {
    let dir = std::env::temp_dir().join(format!("spl-issuer-limits-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).expect("fixture directory");
    let count = Arc::new(AtomicUsize::new(0));
    let requests = Arc::clone(&count);
    let (port, server) = https::start(&dir, false, move |_| {
        Router::new().fallback(move || {
            requests.fetch_add(1, Ordering::SeqCst);
            async { StatusCode::NOT_FOUND }
        })
    })
    .await;
    let origin = format!("https://127.0.0.1:{port}");
    let prefix = format!("{origin}/private-marker");
    let limit = format!("{prefix}{}", "a".repeat(2048 - prefix.len()));
    let ca = dir.join("ca.pem");
    let config = dir.join("absent.toml");
    for issuer in [
        format!("{limit}a"),
        format!("{}\u{e9}", &limit[..2047]),
        format!("{prefix}\u{a0}space"),
        format!("{prefix}\u{85}control"),
        format!("{prefix}\u{9f}control"),
        format!("https://@127.0.0.1:{port}/private-marker"),
    ] {
        let check = check(issuer.clone(), Some(ca.clone())).await;
        let settings = Command::new(env!("CARGO_BIN_EXE_splctl"))
            .args(["auth", "registration-settings", "--config"])
            .arg(&config)
            .args(["--issuer", &issuer])
            .output()
            .expect("registration settings CLI");
        for out in [check, settings] {
            assert!(!out.status.success() && out.stdout.is_empty());
            let reason = String::from_utf8(out.stderr).expect("diagnostic text");
            assert!(reason.contains("absolute HTTPS issuer") && !reason.contains("private-marker"));
        }
    }
    assert_eq!(count.load(Ordering::SeqCst), 0);
    let accepted = check(limit, Some(ca.clone())).await;
    assert!(String::from_utf8_lossy(&accepted.stderr).contains("HTTP 200"));
    assert_eq!(count.load(Ordering::SeqCst), 1);
    server.abort();
    fs::remove_file(ca).expect("remove fixture CA");
    fs::remove_dir(dir).expect("commands must leave no deployment files");
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
        "basic" => {
            document["token_endpoint_auth_methods_supported"] = json!(["client_secret_basic"]);
        }
        "public-only" => document["token_endpoint_auth_methods_supported"] = json!(["none"]),
        "null-methods" => document["token_endpoint_auth_methods_supported"] = json!(null),
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
        ("basic", "PASS"),
        ("public-only", "client_secret_basic"),
        ("null-methods", "invalid discovery"),
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
        assert_eq!(out.status.success(), matches!(scenario, "tenant" | "basic"));
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

#[test]
fn prepares_manual_registration_from_the_configured_origin_offline() {
    let dir = std::env::temp_dir().join(format!("spl-registration-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&dir).expect("fixture directory");
    let config = dir.join("server.toml");
    let data = dir.join("absent");
    fs::write(&config, format!(
        "[server]\npublic_host = 'workspace.example.test'\npublic_port = 9443\ndata_dir = '{}'\n[storage]\nbackend = 'postgres'\ndatabase_url = 'postgres://private-config-marker@unreachable.example.test/unused'\n",
        data.to_str().expect("fixture path").replace('\\', "/")
    )).expect("deployment configuration");
    let settings = |issuer: &str| {
        let mut cmd = Command::new(env!("CARGO_BIN_EXE_splctl"));
        for (key, _) in std::env::vars_os().filter(|(k, _)| k.to_string_lossy().starts_with("SPL_"))
        {
            cmd.env_remove(key);
        }
        cmd.env("HTTPS_PROXY", "http://127.0.0.1:9")
            .env("ALL_PROXY", "http://127.0.0.1:9")
            .env("NO_PROXY", "")
            .args(["auth", "registration-settings", "--config"])
            .arg(&config)
            .args(["--issuer", issuer])
            .output()
            .expect("registration CLI")
    };
    for (issuer, digest) in [
        (
            "https://id.example.test/teams",
            "3f44c165315f1fc33c4cd2af803fcad5c877351b407399263401a16ded59c718",
        ),
        (
            "https://id.example.test/teams/",
            "1c58e73e1bbabe5cffcf56b3b0fc91fb07e16a8c47878ae3e3818316d92f1851",
        ),
        (
            "https://id.example.test/team-b",
            "32281b66eee1eb866e816ef8fd52e586f70525288ea3f8fc30b091c5a1a36ffc",
        ),
    ] {
        let out = settings(issuer);
        assert!(out.status.success());
        let actual: serde_json::Value = serde_json::from_slice(&out.stdout).expect("settings JSON");
        assert_eq!(
            actual,
            json!({
                "redirect_uri": format!("https://workspace.example.test:9443/api/v1/auth/enterprise/oidc/{digest}/callback"),
                "response_type": "code", "grant_type": "authorization_code", "scope": "openid",
                "code_challenge_method": "S256", "token_endpoint_auth_method": "client_secret_basic"
            })
        );
        assert_eq!(out.stderr, b"");
    }
    let prefix = "https://id.example.test/";
    let largest = format!("{prefix}{}", "a".repeat(2046 - prefix.len()) + "\u{e9}");
    assert_eq!(largest.len(), 2048);
    assert!(settings(&largest).status.success());
    let invalid = settings("https://private-marker@id.example.test");
    assert!(!invalid.status.success() && invalid.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&invalid.stderr).contains("private-marker"));
    fs::remove_file(&config).expect("remove fixture");
    let missing = settings("https://id.example.test");
    assert!(!missing.status.success() && missing.stdout.is_empty());
    fs::remove_dir(dir).expect("the command must leave no deployment state");
}
