// SPDX-License-Identifier: AGPL-3.0-only

use std::{
    fs,
    io::Write as _,
    path::Path,
    process::{Command, Output, Stdio},
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
};

use axum::{
    Json, Router,
    body::Body,
    http::{HeaderMap, Response, StatusCode, header},
    response::IntoResponse as _,
    routing::get,
};
use serde_json::json;

#[path = "common/https.rs"]
mod https;

const KEY: &str = "ply_sk_fixture.private-marker";
const CLIENT: &str = "client-under-review";
const SPACE: &str = "spc_Selected";

async fn check(origin: &str, ca: &Path, input: &'static str) -> Output {
    let origin = origin.to_owned();
    let ca = ca.to_owned();
    tokio::task::spawn_blocking(move || {
        let mut child = Command::new(env!("CARGO_BIN_EXE_splctl"))
            .args([
                "auth",
                "check-governance",
                "--server-origin",
                &origin,
                "--client-id",
                CLIENT,
                "--space-id",
                SPACE,
                "--ca-certificate",
            ])
            .arg(ca)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped())
            .spawn()
            .expect("governance CLI");
        // Usage errors can close stdin before reading it.
        let _ = child.stdin.take().unwrap().write_all(input.as_bytes());
        child.wait_with_output().expect("governance CLI result")
    })
    .await
    .expect("CLI task")
}

fn check_server_plane_headers(headers: &HeaderMap) {
    let expected = format!("Bearer {KEY}");
    assert!(headers.get(header::AUTHORIZATION).is_some_and(|value| value == expected.as_str()));
    assert!(!headers.contains_key(header::ORIGIN));
    assert!(!headers.contains_key(header::COOKIE));
}

#[tokio::test]
async fn preflight_requires_exact_application_key_and_active_space_installation() {
    let directory = std::env::temp_dir().join(format!("spl-governance-{}", uuid::Uuid::new_v4()));
    fs::create_dir(&directory).expect("fixture directory");
    let mode = Arc::new(AtomicUsize::new(0));
    let reads = Arc::new([AtomicUsize::new(0), AtomicUsize::new(0), AtomicUsize::new(0)]);
    let fixture_mode = Arc::clone(&mode);
    let fixture_reads = Arc::clone(&reads);
    let (port, server) = https::start(&directory, false, move |_| {
        let key_mode = Arc::clone(&fixture_mode);
        let key_reads = Arc::clone(&fixture_reads);
        let installations_mode = fixture_mode;
        let installations_reads = Arc::clone(&fixture_reads);
        Router::new()
            .route("/server/v1/key", get(move |headers: HeaderMap| {
                check_server_plane_headers(&headers);
                key_reads[0].fetch_add(1, Ordering::SeqCst);
                let mode = key_mode.load(Ordering::SeqCst);
                async move {
                    if mode == 7 {
                        return Response::builder().status(StatusCode::FOUND)
                            .header(header::LOCATION, "/capture").body(Body::empty()).unwrap();
                    }
                    let client = if mode == 1 { "foreign-client" } else { CLIENT };
                    let grants = if mode == 2 { json!(["auth.authz:check", "auth.audit:write"]) } else { json!(["auth.authz:check"]) };
                    Json(json!({"data":{
                        "application_id":"app_Reviewed","client_id":client,"space_id":"spc_Publisher",
                        "grants":grants,"restrict_to":[{"space_id":SPACE,"include_descendants":mode == 3}],
                        "allow_subject_assertion": mode != 4
                    }})).into_response()
                }
            }))
            .route("/server/v1/installations", get(move |headers: HeaderMap| {
                check_server_plane_headers(&headers);
                installations_reads[1].fetch_add(1, Ordering::SeqCst);
                let mode = installations_mode.load(Ordering::SeqCst);
                async move {
                    let space = if mode == 5 { "spc_Foreign" } else { SPACE };
                    let installation = json!({
                        "id":"ins_Selected", "application_id":"app_Reviewed","space_id":space,
                        "scope":if mode == 8 { "group" } else { "space" },"status":"active",
                        "approved_permissions":["auth.authz:check"]
                    });
                    let mut response = json!({"data":[installation]});
                    if mode == 6 {
                        response["next_cursor"] = json!("private-cursor-marker");
                    }
                    if mode == 9 {
                        response["data"] = json!([]);
                    }
                    Json(response)
                }
            }))
            .route("/capture", get(move || {
                fixture_reads[2].fetch_add(1, Ordering::SeqCst);
                async { StatusCode::NO_CONTENT }
            }))
    }).await;
    let origin = format!("https://127.0.0.1:{port}");
    let ca = directory.join("ca.pem");
    let key = concat!("ply_sk_fixture.private-marker", "\r\n");
    let ok = check(&origin, &ca, key).await;
    assert!(ok.status.success(), "{}", String::from_utf8_lossy(&ok.stderr));
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&ok.stdout).unwrap(),
        json!({
            "application_id":"app_Reviewed", "installation_id":"ins_Selected", "space_id":SPACE,
        })
    );
    for (index, reason) in [
        (1, "reviewed OIDC application"),
        (2, "only auth.authz:check"),
        (3, "without descendants"),
        (4, "with by-ID assertions"),
        (5, "selected Space"),
        (6, "complete installation"),
        (7, "did not accept"),
        (8, "does not approve"),
        (9, "one current installation"),
    ] {
        mode.store(index, Ordering::SeqCst);
        let out = check(&origin, &ca, key).await;
        let stderr = String::from_utf8(out.stderr).unwrap();
        assert!(!out.status.success() && out.stdout.is_empty());
        assert!(stderr.contains(reason), "scenario {index} gave {stderr}");
        assert!(!stderr.contains("private-marker") && !stderr.contains("private-cursor-marker"));
    }
    assert_eq!(reads[0].load(Ordering::SeqCst), 10);
    assert_eq!(reads[1].load(Ordering::SeqCst), 5);
    assert_eq!(reads[2].load(Ordering::SeqCst), 0);
    for (target, input) in [(format!("{origin}/alternate"), key), (origin, "invalid\nkey\n")] {
        let out = check(&target, &ca, input).await;
        assert!(!out.status.success() && out.stdout.is_empty());
    }
    assert_eq!(reads[0].load(Ordering::SeqCst), 10);
    server.abort();
    fs::remove_file(ca).expect("remove fixture CA");
    fs::remove_dir(directory).expect("remove fixture directory");
}
